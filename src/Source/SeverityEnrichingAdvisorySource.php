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

namespace mteu\AdvisoryMatcher\Source;

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\Severity;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Resolves an Unknown severity from the advisory's CVE record. A severity a feed stated is never replaced.
 * Wrap it around a CachingAdvisorySource, not inside one, so a lookup that failed is not cached with the answer.
 */
final readonly class SeverityEnrichingAdvisorySource implements AdvisorySource
{
    /**
     * @param int $maxLookupsPerBatch remote lookups per advisoriesFor() call. Stored severities are free.
     *                                NVD allows about 5 requests in 30 seconds without an API key, 50 with one
     */
    public function __construct(
        private AdvisorySource $inner,
        private SeverityLookup $severityLookup,
        private int $maxLookupsPerBatch = 5,
        private LoggerInterface $logger = new NullLogger(),
    ) {
        if ($maxLookupsPerBatch < 0) {
            throw new \InvalidArgumentException('The number of severity lookups per batch cannot be negative.');
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
        $batch = $this->inner->advisoriesFor($packages);
        $severities = $this->severitiesFor($this->unratedCveIdsIn($batch->advisories));

        if ($severities === []) {
            return $batch;
        }

        return new AdvisoryBatch(
            answeredFor: array_map(
                fn (AnsweredPackage $answer): AnsweredPackage => new AnsweredPackage(
                    package: $answer->package,
                    advisories: array_map(
                        fn (Advisory $advisory): Advisory => $this->rated($advisory, $severities),
                        $answer->advisories,
                    ),
                ),
                $batch->answeredFor,
            ),
            failures: $batch->failures,
        );
    }

    /**
     * @param list<Advisory> $advisories
     * @return list<string> without repeats, so an id shared by several advisories is asked once
     */
    private function unratedCveIdsIn(array $advisories): array
    {
        $cveIds = [];

        foreach ($advisories as $advisory) {
            if ($advisory->severity === Severity::Unknown && $advisory->hasCve()) {
                $cveId = strtoupper($advisory->cve);
                $cveIds[$cveId] = $cveId;
            }
        }

        return array_values($cveIds);
    }

    /**
     * @param list<string> $cveIds
     * @return array<string, Severity>
     */
    private function severitiesFor(array $cveIds): array
    {
        $severities = $cveIds === [] ? [] : $this->severityLookup->storedSeveritiesForCves($cveIds);
        $lookups = 0;
        $skipped = 0;
        $givenUp = false;

        foreach ($cveIds as $cveId) {
            if (array_key_exists($cveId, $severities)) {
                continue;
            }

            if ($givenUp || $lookups >= $this->maxLookupsPerBatch) {
                ++$skipped;
                continue;
            }

            ++$lookups;
            $found = $this->severityLookup->severityForCve($cveId);

            if ($found instanceof SourceFailure) {
                // Not a batch failure, because the package was answered. Reporting it would mark the coverage incomplete.
                $this->logger->warning('Could not look up the severity of a CVE.', [
                    'cve' => $cveId,
                    'source' => $found->sourceName,
                    'reason' => $found->reason->value,
                    'detail' => $found->detail,
                ]);
                $givenUp = $found->reason->isTransient();
                continue;
            }

            $severities[$cveId] = $found;
        }

        if ($skipped > 0) {
            $this->logger->info('Left CVE severities unknown until a later batch.', [
                'cves' => $skipped,
                'maxLookupsPerBatch' => $this->maxLookupsPerBatch,
            ]);
        }

        return $severities;
    }

    /**
     * @param array<string, Severity> $severities
     */
    private function rated(Advisory $advisory, array $severities): Advisory
    {
        if ($advisory->severity !== Severity::Unknown) {
            return $advisory;
        }

        $found = $severities[strtoupper($advisory->cve)] ?? null;

        return $found instanceof Severity ? $advisory->withSeverity($found) : $advisory;
    }
}
