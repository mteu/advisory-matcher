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

namespace mteu\AdvisoryMatcher\Source\Nvd;

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\Nvd\NvdAdvisoryNormalizer;
use mteu\AdvisoryMatcher\Clock\SystemClock;
use mteu\AdvisoryMatcher\Package\CpeIdentity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Source\AdvisoryBatch;
use mteu\AdvisoryMatcher\Source\AdvisorySource;
use mteu\AdvisoryMatcher\Source\AnsweredPackage;
use mteu\AdvisoryMatcher\Source\Http\BoundedBodyReader;
use mteu\AdvisoryMatcher\Source\Http\HttpFailureClassifier;
use mteu\AdvisoryMatcher\Source\Http\UserAgent;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final readonly class NvdAdvisorySource implements AdvisorySource
{
    public const string NAME = 'NVD';

    /** Software no package registry ships: the PHP runtime and the platform it runs on. */
    private const array COVERED_ECOSYSTEMS = [Ecosystem::Php, Ecosystem::Platform];

    private NvdApi $api;

    private NvdAdvisoryNormalizer $normalizer;

    public function __construct(
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        #[\SensitiveParameter]
        string $apiKey = '',
        LoggerInterface $logger = new NullLogger(),
        string $userAgent = UserAgent::LIBRARY_DEFAULT,
        ClockInterface $clock = new SystemClock(),
        string $endpoint = 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        BoundedBodyReader $bodyReader = new BoundedBodyReader(),
        HttpFailureClassifier $failureClassifier = new HttpFailureClassifier(),
    ) {
        $this->normalizer = new NvdAdvisoryNormalizer($clock);
        $this->api = new NvdApi(
            $httpClient,
            $requestFactory,
            $bodyReader,
            $failureClassifier,
            $logger,
            $endpoint,
            trim($apiKey),
            new UserAgent($userAgent),
        );
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function coveredEcosystems(): array
    {
        return self::COVERED_ECOSYSTEMS;
    }

    public function advisoriesFor(array $packages): AdvisoryBatch
    {
        $answeredFor = [];

        /** @var array<string, array{failure: SourceFailure, ecosystem: Ecosystem, components: int}> $unanswered */
        $unanswered = [];
        $givenUp = null;

        foreach ($this->queriesFor($packages) as $cpeName => $query) {
            // Once NVD says it is not answering, skip the remaining components to avoid useless api calls.
            $records = $givenUp ?? $this->api->findVulnerabilities($cpeName);

            if ($records instanceof SourceFailure) {
                $unanswered = $this->tally($unanswered, $query, $records);
                $givenUp = $records->reason->isTransient() ? $records : null;
                continue;
            }

            /** @var array<string, list<Advisory>> $advisoriesByPackage */
            $advisoriesByPackage = [];

            foreach ($query['packages'] as $package) {
                $key = $package->package->toString();
                $advisoriesByPackage[$key] ??= $this->normalizeAll($records, $package->package, $query);
                $answeredFor[] = new AnsweredPackage($package, advisories: $advisoriesByPackage[$key]);
            }
        }

        return new AdvisoryBatch(
            answeredFor: $answeredFor,
            failures: $this->failuresFrom($unanswered),
        );
    }

    /**
     * @param list<PackageRef> $packages
     * @return array<string, array{identity: CpeIdentity, release: string, ecosystem: Ecosystem, packages: list<PackageRef>}>
     */
    private function queriesFor(array $packages): array
    {
        $queries = [];

        foreach ($packages as $package) {
            if (!in_array($package->ecosystem, self::COVERED_ECOSYSTEMS, true)) {
                continue;
            }

            $identity = CpeIdentity::forPackage($package->package);
            $cpeName = $identity?->nameForVersion($package->version) ?? '';

            if (!$identity instanceof CpeIdentity || $cpeName === '') {
                continue;
            }

            $queries[$cpeName] ??= [
                'identity' => $identity,
                'release' => $identity->releaseOf($package->version),
                'ecosystem' => $package->ecosystem,
                'packages' => [],
            ];
            $queries[$cpeName]['packages'][] = $package;
        }

        return $queries;
    }

    /**
     * @param list<array<string, mixed>> $records
     * @param array{identity: CpeIdentity, release: string, ecosystem: Ecosystem, packages: list<PackageRef>} $query
     * @return list<Advisory>
     */
    private function normalizeAll(array $records, PackageUrl $package, array $query): array
    {
        $advisories = [];

        foreach ($records as $cve) {
            // A withdrawn record describes no vulnerability. The query asks NVD to leave them out.
            if (($cve['vulnStatus'] ?? null) !== 'Rejected') {
                $advisories[] = $this->normalizer->normalize($cve, $package, $query['identity'], $query['release']);
            }
        }

        return $advisories;
    }

    /**
     * The API does not know which ecosystem it was asked for, so the failure is
     * filed under the ecosystem of the query here.
     *
     * @param array<string, array{failure: SourceFailure, ecosystem: Ecosystem, components: int}> $unanswered
     * @param array{identity: CpeIdentity, release: string, ecosystem: Ecosystem, packages: list<PackageRef>} $query
     * @return array<string, array{failure: SourceFailure, ecosystem: Ecosystem, components: int}>
     */
    private function tally(array $unanswered, array $query, SourceFailure $failure): array
    {
        $key = $query['ecosystem']->value . ':' . $failure->reason->value;

        $unanswered[$key] = [
            'failure' => $unanswered[$key]['failure'] ?? $failure,
            'ecosystem' => $query['ecosystem'],
            'components' => ($unanswered[$key]['components'] ?? 0) + count($query['packages']),
        ];

        return $unanswered;
    }

    /**
     * @param array<string, array{failure: SourceFailure, ecosystem: Ecosystem, components: int}> $unanswered
     * @return list<SourceFailure>
     */
    private function failuresFrom(array $unanswered): array
    {
        $failures = [];

        foreach ($unanswered as $entry) {
            $failure = $entry['failure'];
            $failures[] = new SourceFailure(
                sourceName: $failure->sourceName,
                ecosystem: $entry['ecosystem'],
                reason: $failure->reason,
                detail: sprintf('%d component(s) left unanswered. %s', $entry['components'], $failure->detail),
                retryAfterSeconds: $failure->retryAfterSeconds,
            );
        }

        return $failures;
    }
}
