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

namespace mteu\AdvisoryMatcher\Advisory\Nvd;

use mteu\AdvisoryMatcher\Advisory\Severity;

/**
 * @internal
 */
final readonly class NvdSeverityReader
{
    private const array METRIC_KEYS = [
        'cvssMetricV40',
        'cvssMetricV31',
        'cvssMetricV30',
        'cvssMetricV2',
    ];

    /**
     * @param array<string, mixed> $cve the `cve` object of one NVD `vulnerabilities` entry
     */
    public function severityOf(array $cve): Severity
    {
        $allMetrics = $cve['metrics'] ?? null;

        if (!is_array($allMetrics)) {
            return Severity::Unknown;
        }

        foreach (self::METRIC_KEYS as $metricKey) {
            $metrics = $allMetrics[$metricKey] ?? null;

            if (!is_array($metrics) || $metrics === []) {
                continue;
            }

            $metric = $this->chosenMetric($metrics);
            $cvssData = is_array($metric['cvssData'] ?? null) ? $metric['cvssData'] : [];
            $statedBand = $this->statedBand($metric, $cvssData);

            $stated = Severity::fromFeedValue($statedBand);

            if ($stated !== Severity::Unknown) {
                return $stated;
            }

            $baseScore = $cvssData['baseScore'] ?? null;

            if (is_numeric($baseScore)) {
                return Severity::fromCvssScore((float)$baseScore);
            }
        }

        return Severity::Unknown;
    }

    /**
     * @param array<mixed> $metrics
     * @return array<mixed>
     */
    private function chosenMetric(array $metrics): array
    {
        $chosen = [];

        foreach ($metrics as $metric) {
            if (!is_array($metric)) {
                continue;
            }

            if (($metric['type'] ?? null) === 'Primary') {
                return $metric;
            }

            if ($chosen === []) {
                $chosen = $metric;
            }
        }

        return $chosen;
    }

    /**
     * @param array<mixed> $metric
     * @param array<mixed> $cvssData
     */
    private function statedBand(array $metric, array $cvssData): string
    {
        foreach ([$cvssData['baseSeverity'] ?? null, $metric['baseSeverity'] ?? null] as $baseSeverity) {
            if (is_string($baseSeverity) && trim($baseSeverity) !== '') {
                return $baseSeverity;
            }
        }

        return '';
    }
}
