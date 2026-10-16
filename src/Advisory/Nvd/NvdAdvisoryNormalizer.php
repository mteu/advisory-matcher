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

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\AdvisoryReference;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\CpeIdentity;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Version\AffectedVersions;
use mteu\AdvisoryMatcher\Version\VersionRange;
use Psr\Clock\ClockInterface;

/**
 * @internal
 */
final readonly class NvdAdvisoryNormalizer
{
    private const array VERSION_BOUND_FIELDS = [
        'versionStartIncluding',
        'versionStartExcluding',
        'versionEndExcluding',
        'versionEndIncluding',
    ];

    private const array METRIC_KEYS = [
        'cvssMetricV40',
        'cvssMetricV31',
        'cvssMetricV30',
        'cvssMetricV2',
    ];

    private const int TITLE_LENGTH = 120;

    public function __construct(
        private ClockInterface $clock,
    ) {
    }

    /**
     * @param array<string, mixed> $cve the `cve` object of one NVD `vulnerabilities` entry
     * @param string $installedRelease picks which of a multi-branch CVE's fixes is the upgrade target; '' names the lowest
     */
    public function normalize(
        array $cve,
        PackageUrl $package,
        CpeIdentity $identity,
        string $installedRelease,
    ): Advisory {
        $id = is_string($cve['id'] ?? null) ? $cve['id'] : 'CVE-unknown';
        $matches = $this->vulnerableMatchesFor($cve, $identity->criteriaPrefix());

        return new Advisory(
            advisoryId: 'NVD-' . $id,
            package: $package,
            title: $this->extractTitle($cve),
            link: 'https://nvd.nist.gov/vuln/detail/' . rawurlencode($id),
            // Every NVD record is a CVE record, so the id is the CVE
            cve: str_starts_with($id, 'CVE-') ? $id : '',
            affectedVersions: $this->extractVersionRanges($matches),
            reportedAt: $this->extractReportedAt($cve['published'] ?? null),
            severity: $this->extractSeverity($cve),
            references: [new AdvisoryReference('NVD', $id)],
            firstPatchedVersion: $this->extractFirstPatchedVersion($matches, $installedRelease),
        );
    }

    /**
     * @param array<string, mixed> $cve
     * @return list<array{criteria: string, bounds: array<string, string>}>
     */
    private function vulnerableMatchesFor(array $cve, string $criteriaPrefix): array
    {
        $matches = [];

        foreach ($this->cpeMatches($cve) as $cpeMatch) {
            $criteria = $cpeMatch['criteria'] ?? null;

            if (($cpeMatch['vulnerable'] ?? false) !== true
                || !is_string($criteria)
                || !str_starts_with($criteria, $criteriaPrefix)
            ) {
                continue;
            }

            $bounds = [];

            foreach (self::VERSION_BOUND_FIELDS as $field) {
                $bound = $cpeMatch[$field] ?? null;

                if (is_string($bound) && $bound !== '') {
                    $bounds[$field] = $bound;
                }
            }

            $matches[] = ['criteria' => $criteria, 'bounds' => $bounds];
        }

        return $matches;
    }

    /**
     * @param array<string, mixed> $cve
     * @return iterable<int, array<mixed>>
     */
    private function cpeMatches(array $cve): iterable
    {
        $configurations = $cve['configurations'] ?? null;

        if (!is_array($configurations)) {
            return;
        }

        foreach ($configurations as $configuration) {
            $nodes = is_array($configuration) ? ($configuration['nodes'] ?? null) : null;

            foreach (is_array($nodes) ? $nodes : [] as $node) {
                $cpeMatches = is_array($node) ? ($node['cpeMatch'] ?? null) : null;

                foreach (is_array($cpeMatches) ? $cpeMatches : [] as $cpeMatch) {
                    if (is_array($cpeMatch)) {
                        yield $cpeMatch;
                    }
                }
            }
        }
    }

    /**
     * @param list<array{criteria: string, bounds: array<string, string>}> $matches
     */
    private function extractVersionRanges(array $matches): AffectedVersions
    {
        $ranges = [];

        try {
            foreach ($matches as $cpeMatch) {
                $ranges[] = $this->rangeFrom($cpeMatch);
            }
        } catch (\InvalidArgumentException) {
            // Dropping only the unreadable range could turn an affected version into a clean one
            return new AffectedVersions();
        }

        return new AffectedVersions($ranges);
    }

    /**
     * @param array{criteria: string, bounds: array<string, string>} $cpeMatch
     */
    private function rangeFrom(array $cpeMatch): VersionRange
    {
        $bounds = $cpeMatch['bounds'];
        $range = new VersionRange(
            from: $bounds['versionStartIncluding'] ?? '',
            after: $bounds['versionStartExcluding'] ?? '',
            before: $bounds['versionEndExcluding'] ?? '',
            through: $bounds['versionEndIncluding'] ?? '',
        );

        if ($range->bounds() !== []) {
            return $range;
        }

        // No bounds: One exact release, or `*`/`-` for every release there is.
        $version = explode(':', $cpeMatch['criteria'])[5] ?? '';

        return in_array($version, ['', '*', '-'], true) ? new VersionRange() : VersionRange::exactly($version);
    }

    /**
     * @param list<array{criteria: string, bounds: array<string, string>}> $matches
     */
    private function extractFirstPatchedVersion(array $matches, string $installedRelease): string
    {
        $fixed = [];

        foreach ($matches as $cpeMatch) {
            if (array_key_exists('versionEndExcluding', $cpeMatch['bounds'])) {
                $fixed[] = $cpeMatch['bounds']['versionEndExcluding'];
            }
        }

        if ($fixed === [] || $installedRelease === '') {
            return $this->lowestVersion($fixed);
        }

        $upgrades = array_values(array_filter(
            $fixed,
            static fn (string $version): bool => version_compare($version, $installedRelease, '>'),
        ));

        return $this->lowestVersion($upgrades === [] ? $fixed : $upgrades);
    }

    /**
     * @param list<string> $versions
     */
    private function lowestVersion(array $versions): string
    {
        $lowest = '';

        foreach ($versions as $version) {
            if ($lowest === '' || version_compare($version, $lowest, '<')) {
                $lowest = $version;
            }
        }

        return $lowest;
    }

    /**
     * @param array<string, mixed> $cve
     */
    private function extractTitle(array $cve): string
    {
        $descriptions = $cve['descriptions'] ?? null;

        foreach (is_array($descriptions) ? $descriptions : [] as $description) {
            // NVD carries the same text in several languages. Let's take the English one.
            if (!is_array($description)
                || ($description['lang'] ?? null) !== 'en'
                || !is_string($description['value'] ?? null)
                || trim($description['value']) === ''
            ) {
                continue;
            }

            $value = trim($description['value']);

            return mb_strlen($value) > self::TITLE_LENGTH
                ? mb_substr($value, 0, self::TITLE_LENGTH) . '...'
                : $value;
        }

        return 'Security vulnerability';
    }

    /**
     * @param array<string, mixed> $cve
     */
    private function extractSeverity(array $cve): Severity
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

    private function extractReportedAt(mixed $published): \DateTimeImmutable
    {
        if (is_string($published) && trim($published) !== '') {
            try {
                return new \DateTimeImmutable($published, new \DateTimeZone('UTC'));
            } catch (\DateMalformedStringException) {
                // The feed sent something that is not a date.
            }
        }

        return $this->clock->now();
    }
}
