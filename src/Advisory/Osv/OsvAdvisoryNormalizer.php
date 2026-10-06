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

namespace mteu\AdvisoryMatcher\Advisory\Osv;

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\AdvisoryReference;
use mteu\AdvisoryMatcher\Advisory\Cvss\CvssV3Vector;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Version\AffectedVersions;
use mteu\AdvisoryMatcher\Version\VersionRange;
use Psr\Clock\ClockInterface;

/**
 * @internal
 */
final readonly class OsvAdvisoryNormalizer
{
    public function __construct(
        private ClockInterface $clock,
    ) {
    }

    /**
     * @param array<string, mixed> $vulnerability one entry of OSV's `vulns`
     * @param array<string, mixed> $affected the `affected` entry naming this package
     */
    public function normalize(
        array $vulnerability,
        string $packageName,
        Ecosystem $ecosystem,
        array $affected,
    ): Advisory {
        $id = is_string($vulnerability['id'] ?? null) ? $vulnerability['id'] : 'OSV-unknown';

        return new Advisory(
            advisoryId: 'OSV-' . $id,
            packageName: $packageName,
            ecosystem: $ecosystem,
            title: $this->extractTitle($vulnerability),
            link: $this->extractLink($vulnerability, $id),
            cve: $this->extractCve($vulnerability),
            affectedVersions: $this->extractVersionRanges($affected),
            reportedAt: $this->extractReportedAt($vulnerability),
            severity: $this->extractSeverity($vulnerability),
            references: [new AdvisoryReference('OSV', $id)],
            firstPatchedVersion: $this->extractFirstPatchedVersion($affected),
        );
    }

    /**
     * @param array<string, mixed> $vulnerability
     */
    private function extractTitle(array $vulnerability): string
    {
        $summary = is_string($vulnerability['summary'] ?? null) ? $vulnerability['summary'] : '';
        if ($summary !== '') {
            return $summary;
        }

        $details = is_string($vulnerability['details'] ?? null) ? $vulnerability['details'] : '';
        if ($details !== '') {
            return $details;
        }

        return 'Security vulnerability';
    }

    /**
     * @param array<string, mixed> $affected
     */
    private function extractVersionRanges(array $affected): AffectedVersions
    {
        $ranges = [];

        try {
            foreach ($this->versionRangeEvents($affected) as $events) {
                $ranges = [...$ranges, ...$this->rangesFrom($events)];
            }
        } catch (\InvalidArgumentException) {
            // Dropping only the unreadable range could turn an affected version into a clean one
            return new AffectedVersions();
        }

        return new AffectedVersions($ranges);
    }

    /**
     * @param list<array<mixed>> $events
     * @return list<VersionRange>
     */
    private function rangesFrom(array $events): array
    {
        $ranges = [];
        $openedAt = null;
        $rangeHasOpened = false;

        foreach ($events as $event) {
            if (is_string($event['introduced'] ?? null)) {
                // While a range is open, a later `introduced` changes nothing,
                // so the versions between them are affected either way.
                $openedAt ??= $event['introduced'];
                $rangeHasOpened = true;
                continue;
            }

            $fixed = is_string($event['fixed'] ?? null) ? $event['fixed'] : '';
            $lastAffected = is_string($event['last_affected'] ?? null) && $fixed === '' ? $event['last_affected'] : '';

            if ($fixed === '' && $lastAffected === '') {
                continue;
            }

            if ($openedAt !== null) {
                $ranges[] = new VersionRange(from: $openedAt, before: $fixed, through: $lastAffected);
                $openedAt = null;
            } elseif (!$rangeHasOpened) {
                $ranges[] = new VersionRange(before: $fixed, through: $lastAffected);
            }
        }

        if ($openedAt !== null) {
            $ranges[] = new VersionRange(from: $openedAt);
        }

        return $ranges;
    }

    /**
     * @param array<string, mixed> $affected
     */
    private function extractFirstPatchedVersion(array $affected): string
    {
        $fixed = [];

        foreach ($this->versionRangeEvents($affected) as $events) {
            foreach ($events as $event) {
                if (is_string($event['fixed'] ?? null)) {
                    $fixed[] = $event['fixed'];
                }
            }
        }

        return $this->lowestVersion($fixed);
    }

    /**
     * @param array<string, mixed> $affected
     * @return iterable<int, list<array<mixed>>>
     */
    private function versionRangeEvents(array $affected): iterable
    {
        if (!is_array($affected['ranges'] ?? null)) {
            return;
        }

        foreach ($affected['ranges'] as $range) {
            if (!is_array($range) || !is_array($range['events'] ?? null)) {
                continue;
            }

            if (is_string($range['type'] ?? null) && strtoupper($range['type']) === 'GIT') {
                continue;
            }

            $events = [];
            foreach ($range['events'] as $event) {
                if (is_array($event)) {
                    $events[] = $event;
                }
            }

            yield $events;
        }
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
     * @param array<string, mixed> $vulnerability
     */
    private function extractSeverity(array $vulnerability): Severity
    {
        $databaseSpecific = $vulnerability['database_specific'] ?? null;
        if (is_array($databaseSpecific) && is_string($databaseSpecific['severity'] ?? null)) {
            $labelled = Severity::fromFeedValue($databaseSpecific['severity']);

            if ($labelled !== Severity::Unknown) {
                return $labelled;
            }
        }

        if (is_array($vulnerability['severity'] ?? null)) {
            foreach ($vulnerability['severity'] as $entry) {
                $scored = is_array($entry) ? $this->severityOfCvssEntry($entry['score'] ?? null) : Severity::Unknown;

                if ($scored !== Severity::Unknown) {
                    return $scored;
                }
            }
        }

        return Severity::Unknown;
    }

    private function severityOfCvssEntry(mixed $score): Severity
    {
        if (is_numeric($score)) {
            return Severity::fromCvssScore((float)$score);
        }

        if (!is_string($score) || !str_starts_with($score, 'CVSS:3.')) {
            return Severity::Unknown;
        }

        try {
            return Severity::fromCvssScore(CvssV3Vector::fromString($score)->baseScore());
        } catch (\InvalidArgumentException) {
            // A malformed vector states nothing usable, like a missing one.
            return Severity::Unknown;
        }
    }

    /**
     * @param array<string, mixed> $vulnerability
     */
    private function extractLink(array $vulnerability, string $id): string
    {
        if (is_array($vulnerability['references'] ?? null)) {
            foreach ($vulnerability['references'] as $reference) {
                if (!is_array($reference) || !is_string($reference['url'] ?? null)) {
                    continue;
                }

                $url = $this->safeUrl($reference['url']);
                if ($url !== '') {
                    return $url;
                }
            }
        }

        return 'https://osv.dev/vulnerability/' . $id;
    }

    private function safeUrl(string $url): string
    {
        $url = trim($url);

        return Advisory::isSafeLink($url) ? $url : '';
    }

    /**
     * @param array<string, mixed> $vulnerability
     */
    private function extractCve(array $vulnerability): string
    {
        if (is_array($vulnerability['aliases'] ?? null)) {
            foreach ($vulnerability['aliases'] as $alias) {
                if (is_string($alias) && str_starts_with($alias, 'CVE-')) {
                    return $alias;
                }
            }
        }

        return '';
    }

    /**
     * @param array<string, mixed> $vulnerability
     */
    private function extractReportedAt(array $vulnerability): \DateTimeImmutable
    {
        $published = $vulnerability['published'] ?? null;

        if (is_string($published) && trim($published) !== '') {
            try {
                return new \DateTimeImmutable($published);
            } catch (\DateMalformedStringException) {
                // The feed sent something that is not a date.
            }
        }

        return $this->clock->now();
    }
}
