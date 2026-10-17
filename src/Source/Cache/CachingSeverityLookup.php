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

use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Source\SeverityLookup;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

final readonly class CachingSeverityLookup implements SeverityLookup
{
    private const string KEY_PREFIX = 'cve_severity_v1_';

    private const int KNOWN_TTL_SECONDS = 7 * 24 * 60 * 60;

    // NVD often scores a CVE days after publishing it, so an unscored answer is asked again sooner.
    private const int UNKNOWN_TTL_SECONDS = 24 * 60 * 60;

    public function __construct(
        private SeverityLookup $inner,
        private CacheInterface $cache,
        private LoggerInterface $logger = new NullLogger(),
    ) {
    }

    public function severityForCve(string $cveId): Severity|SourceFailure
    {
        $stored = $this->storedSeveritiesForCves([$cveId]);

        if (array_key_exists($cveId, $stored)) {
            return $stored[$cveId];
        }

        $severity = $this->inner->severityForCve($cveId);

        if ($severity instanceof SourceFailure) {
            return $severity;
        }

        $ttl = $severity === Severity::Unknown ? self::UNKNOWN_TTL_SECONDS : self::KNOWN_TTL_SECONDS;

        if (!$this->cache->set($this->keyFor($cveId), $severity->value, $ttl)) {
            $this->logger->warning('Could not store a CVE severity.', ['cve' => $cveId]);
        }

        return $severity;
    }

    public function storedSeveritiesForCves(array $cveIds): array
    {
        $idsByKey = [];

        foreach ($cveIds as $cveId) {
            $idsByKey[$this->keyFor($cveId)] = $cveId;
        }

        $stored = [];

        foreach ($this->cache->getMultiple(array_keys($idsByKey)) as $key => $cached) {
            $severity = is_string($cached) ? Severity::tryFrom($cached) : null;

            if ($severity instanceof Severity) {
                $stored[$idsByKey[$key]] = $severity;
            }
        }

        $missing = array_values(array_diff($cveIds, array_keys($stored)));

        return $stored + $this->inner->storedSeveritiesForCves($missing);
    }

    private function keyFor(string $cveId): string
    {
        // Hashed, because the id comes from a feed and PSR-16 reserves some characters in keys.
        return self::KEY_PREFIX . sha1(strtoupper($cveId));
    }
}
