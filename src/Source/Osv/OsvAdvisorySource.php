<?php

declare(strict_types=1);

/*
 * This file is part of the library "mteu/advisory-matcher".
 *
 * Copyright (c) 2026 Martin Adler <mteu@mailbox.org>
 *
 * For the full copyright and license information, please read the
 * LICENSE.md file that was distributed with this source code.
 */

namespace mteu\AdvisoryMatcher\Source\Osv;

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\Osv\OsvAdvisoryNormalizer;
use mteu\AdvisoryMatcher\Clock\SystemClock;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\AdvisoryBatch;
use mteu\AdvisoryMatcher\Source\AdvisorySource;
use mteu\AdvisoryMatcher\Source\AnsweredPackage;
use mteu\AdvisoryMatcher\Source\Cache\NullCache;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\Http\BoundedBodyReader;
use mteu\AdvisoryMatcher\Source\Http\HttpFailureClassifier;
use mteu\AdvisoryMatcher\Source\Http\UserAgent;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

final readonly class OsvAdvisorySource implements AdvisorySource
{
    public const string NAME = 'OSV';

    private const int MAX_BATCH_SIZE = 1000;

    private const int RECORD_TTL_SECONDS = 7 * 24 * 60 * 60;

    private const string RECORD_KEY_PREFIX = 'record_v1_';

    private OsvApi $api;

    private OsvAdvisoryNormalizer $normalizer;

    public function __construct(
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory,
        private CacheInterface $recordCache = new NullCache(),
        private LoggerInterface $logger = new NullLogger(),
        string $userAgent = UserAgent::LIBRARY_DEFAULT,
        ClockInterface $clock = new SystemClock(),
        string $endpoint = 'https://api.osv.dev/v1/',
        BoundedBodyReader $bodyReader = new BoundedBodyReader(),
        HttpFailureClassifier $failureClassifier = new HttpFailureClassifier(),
    ) {
        $this->normalizer = new OsvAdvisoryNormalizer($clock);
        $this->api = new OsvApi(
            $httpClient,
            $requestFactory,
            $streamFactory,
            $bodyReader,
            $failureClassifier,
            $logger,
            $endpoint,
            new UserAgent($userAgent),
        );
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function coveredEcosystems(): array
    {
        return [
            Ecosystem::Composer,
            Ecosystem::Npm,
        ];
    }

    public function advisoriesFor(array $packages): AdvisoryBatch
    {
        [$queries, $refused] = $this->queriesFor($packages);

        /** @var array<string, array{ecosystem: Ecosystem, failure: OsvCallFailure, packages: int}> $unanswered */
        $unanswered = [];

        foreach ($refused as $package) {
            $unanswered = $this->tally($unanswered, $package->ecosystem, 1, new OsvCallFailure(
                FailureReason::Rejected,
                'A package name that is not valid UTF-8 was not sent.',
            ));
        }

        $asked = [];

        foreach (array_chunk($queries, self::MAX_BATCH_SIZE) as $chunk) {
            $found = $this->api->findVulnerabilities($chunk);

            if ($found instanceof OsvCallFailure) {
                foreach ($chunk as $query) {
                    $unanswered = $this->tally($unanswered, $query->ecosystem, count($query->packages), $found);
                }

                continue;
            }

            foreach ($chunk as $position => $query) {
                $asked[] = [$query, $this->distinctReferences($found[$position])];
            }
        }

        [$records, $unreadable] = $this->hydrate(array_merge(...array_map(
            static fn (array $answer): array => $answer[1],
            $asked,
        )));

        $answeredFor = [];

        foreach ($asked as [$query, $references]) {
            $failures = $this->unreadableAmong($references, $unreadable);

            if ($failures !== []) {
                $unanswered = $this->tally($unanswered, $query->ecosystem, count($query->packages), $failures[0]);
                continue;
            }

            // OSV is asked by name, so every version of the name shares one answer.
            $advisories = [];
            foreach ($references as $reference) {
                $advisories[] = $this->normalize($records[$reference->id] ?? [], $query);
            }

            foreach ($query->packages as $package) {
                $answeredFor[] = new AnsweredPackage($package, advisories: $advisories);
            }
        }

        return new AdvisoryBatch(
            answeredFor: $answeredFor,
            failures: $this->failuresFrom($unanswered),
        );
    }

    /**
     * @param list<PackageRef> $packages
     * @return array{list<OsvQuery>, list<PackageRef>}
     */
    private function queriesFor(array $packages): array
    {
        $covered = $this->coveredEcosystems();
        $grouped = [];
        $refused = [];

        foreach ($packages as $package) {
            if (!in_array($package->ecosystem, $covered, true)) {
                continue;
            }

            if (preg_match('//u', $package->name) !== 1) {
                $refused[] = $package;
                continue;
            }

            $grouped[$package->ecosystem->value . '|' . $package->name][] = $package;
        }

        $queries = [];

        foreach ($grouped as $group) {
            $queries[] = new OsvQuery($group[0]->ecosystem, $group[0]->name, $group);
        }

        return [$queries, $refused];
    }

    /**
     * @param list<OsvVulnerabilityReference> $references
     * @return list<OsvVulnerabilityReference>
     */
    private function distinctReferences(array $references): array
    {
        $distinct = [];
        $seen = [];

        foreach ($references as $reference) {
            if (!array_key_exists($reference->id, $seen)) {
                $seen[$reference->id] = true;
                $distinct[] = $reference;
            }
        }

        return $distinct;
    }

    /**
     * @param list<OsvVulnerabilityReference> $references
     * @return array{array<string, array<string, mixed>>, array<string, OsvCallFailure>}
     */
    private function hydrate(array $references): array
    {
        $records = [];
        $unreadable = [];
        $givenUp = null;

        foreach ($this->distinctReferences($references) as $reference) {
            if ($givenUp instanceof OsvCallFailure) {
                $unreadable[$reference->id] = $givenUp;
                continue;
            }

            $cacheKey = self::RECORD_KEY_PREFIX . sha1($reference->id . "\0" . $reference->modified);
            $cached = $this->cachedRecord($cacheKey, $reference->id);

            if ($cached !== []) {
                $records[$reference->id] = $cached;
                continue;
            }

            $record = $this->api->fetchVulnerability($reference->id);

            if ($record instanceof OsvCallFailure) {
                $unreadable[$reference->id] = $record;
                $givenUp = $record->reason->isTransient() ? $record : null;
                continue;
            }

            if (!$this->recordCache->set($cacheKey, $record, self::RECORD_TTL_SECONDS)) {
                $this->logger->warning('Could not store an OSV vulnerability record.', ['id' => $reference->id]);
            }

            $records[$reference->id] = $record;
        }

        return [$records, $unreadable];
    }

    /**
     * @return array<string, mixed>
     */
    private function cachedRecord(string $cacheKey, string $id): array
    {
        $cached = $this->recordCache->get($cacheKey);

        if (!is_array($cached) || ($cached['id'] ?? null) !== $id) {
            return [];
        }

        $record = [];

        foreach ($cached as $key => $value) {
            if (is_string($key)) {
                $record[$key] = $value;
            }
        }

        return $record;
    }

    /**
     * @param list<OsvVulnerabilityReference> $references
     * @param array<string, OsvCallFailure> $unreadable
     * @return list<OsvCallFailure>
     */
    private function unreadableAmong(array $references, array $unreadable): array
    {
        $failures = [];

        foreach ($references as $reference) {
            if (array_key_exists($reference->id, $unreadable)) {
                $failures[] = $unreadable[$reference->id];
            }
        }

        return $failures;
    }

    /**
     * @param array<string, mixed> $record
     */
    private function normalize(array $record, OsvQuery $query): Advisory
    {
        return $this->normalizer->normalize($record, $query->package(), $this->affectedEntryFor($record, $query));
    }

    /**
     * @param array<string, mixed> $record
     * @return array<string, mixed>
     */
    private function affectedEntryFor(array $record, OsvQuery $query): array
    {
        $ranges = [];
        $affectedEntries = is_array($record['affected'] ?? null) ? $record['affected'] : [];

        foreach ($affectedEntries as $affected) {
            if (!is_array($affected) || !$this->namesPackage($affected['package'] ?? null, $query)) {
                continue;
            }

            foreach (is_array($affected['ranges'] ?? null) ? $affected['ranges'] : [] as $range) {
                $ranges[] = $range;
            }
        }

        return ['ranges' => $ranges];
    }

    private function namesPackage(mixed $package, OsvQuery $query): bool
    {
        if (!is_array($package) || !is_string($package['ecosystem'] ?? null) || !is_string($package['name'] ?? null)) {
            return false;
        }

        $ecosystem = $package['ecosystem'];
        $label = $query->label();

        if ($ecosystem !== $label && !str_starts_with($ecosystem, $label . ':')) {
            return false;
        }

        return strtolower($package['name']) === strtolower($query->name);
    }

    /**
     * @param array<string, array{ecosystem: Ecosystem, failure: OsvCallFailure, packages: int}> $unanswered
     * @return array<string, array{ecosystem: Ecosystem, failure: OsvCallFailure, packages: int}>
     */
    private function tally(array $unanswered, Ecosystem $ecosystem, int $packages, OsvCallFailure $failure): array
    {
        $key = $ecosystem->value . '|' . $failure->reason->value;

        $unanswered[$key] = [
            'ecosystem' => $ecosystem,
            'failure' => $unanswered[$key]['failure'] ?? $failure,
            'packages' => ($unanswered[$key]['packages'] ?? 0) + $packages,
        ];

        return $unanswered;
    }

    /**
     * @param array<string, array{ecosystem: Ecosystem, failure: OsvCallFailure, packages: int}> $unanswered
     * @return list<SourceFailure>
     */
    private function failuresFrom(array $unanswered): array
    {
        $failures = [];

        foreach ($unanswered as $entry) {
            $failures[] = $entry['failure']->toSourceFailure(
                self::NAME,
                $entry['ecosystem'],
                sprintf('%d package(s) left unanswered. %s', $entry['packages'], $entry['failure']->detail),
            );
        }

        return $failures;
    }
}
