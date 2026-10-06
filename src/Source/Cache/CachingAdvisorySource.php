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

namespace mteu\AdvisoryMatcher\Source\Cache;

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Source\AdvisoryBatch;
use mteu\AdvisoryMatcher\Source\AdvisorySource;
use mteu\AdvisoryMatcher\Source\AnsweredPackage;
use mteu\AdvisoryMatcher\Source\PackageRef;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

final readonly class CachingAdvisorySource implements AdvisorySource
{
    // Bump when the encoded layout changes, so old entries are never read.
    private const int SCHEMA_VERSION = 4;

    public function __construct(
        private AdvisorySource $inner,
        private CacheInterface $cache,
        private int $ttlSeconds = 3600,
        private LoggerInterface $logger = new NullLogger(),
        private CachedAnswerCodec $codec = new CachedAnswerCodec(),
    ) {
        if ($ttlSeconds < 1) {
            throw new \InvalidArgumentException('A cache TTL has to be at least one second.');
        }
    }

    public function name(): string
    {
        return $this->inner->name();
    }

    public function coveredEcosystems(): array
    {
        return $this->inner->coveredEcosystems();
    }

    public function advisoriesFor(array $packages): AdvisoryBatch
    {
        $packagesByKey = $this->coveredPackagesByKey($packages);

        if ($packagesByKey === []) {
            return new AdvisoryBatch();
        }

        $answeredFromCache = [];

        foreach ($this->readEntries(array_keys($packagesByKey)) as $key => $advisories) {
            $answeredFromCache[] = new AnsweredPackage($packagesByKey[$key], $advisories);
            unset($packagesByKey[$key]);
        }

        $cached = new AdvisoryBatch(answeredFor: $answeredFromCache);

        if ($packagesByKey === []) {
            return $cached;
        }

        $fetched = $this->inner->advisoriesFor(array_values($packagesByKey));
        $this->store($packagesByKey, $fetched);

        return $cached->merge($fetched);
    }

    /**
     * @param list<PackageRef> $packages
     * @return array<string, PackageRef>
     */
    private function coveredPackagesByKey(array $packages): array
    {
        $covered = $this->inner->coveredEcosystems();
        $packagesByKey = [];

        foreach ($packages as $package) {
            if (in_array($package->ecosystem, $covered, true)) {
                $packagesByKey[$this->keyFor($package)] = $package;
            }
        }

        return $packagesByKey;
    }

    /**
     * @param array<string, PackageRef> $packagesByKey
     */
    private function store(array $packagesByKey, AdvisoryBatch $fetched): void
    {
        $entries = [];

        foreach ($packagesByKey as $key => $package) {
            if ($fetched->wasAnsweredFor($package)) {
                $entries[$key] = $this->codec->encode($fetched->advisoriesFor($package));
            }
        }

        if ($entries !== [] && !$this->cache->setMultiple($entries, $this->ttlSeconds)) {
            $this->logger->warning('Could not store cached advisory answers.', [
                'source' => $this->inner->name(),
                'entries' => count($entries),
            ]);
        }
    }

    /**
     * @param list<string> $keys
     * @return array<string, list<Advisory>>
     */
    private function readEntries(array $keys): array
    {
        $entries = [];

        foreach ($this->cache->getMultiple($keys) as $key => $value) {
            if ($value === null) {
                continue;
            }

            try {
                $entries[(string) $key] = $this->codec->decode($value);
            } catch (UnreadableCacheEntry $exception) {
                // Dropped so the package is fetched again rather than reported as checked.
                $this->logger->warning('Discarding an unreadable cached advisory entry.', [
                    'source' => $this->inner->name(),
                    'cacheKey' => (string) $key,
                    'exception' => $exception,
                ]);
                $this->cache->delete((string) $key);
            }
        }

        return $entries;
    }

    private function keyFor(PackageRef $package): string
    {
        $digest = hash('sha256', implode("\0", [
            $this->inner->name(),
            $package->ecosystem->value,
            $package->name,
            $package->version,
        ]));

        return 'advisory_v' . self::SCHEMA_VERSION . '_' . substr($digest, 0, 40);
    }
}
