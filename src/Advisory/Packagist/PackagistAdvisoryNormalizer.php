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

namespace mteu\AdvisoryMatcher\Advisory\Packagist;

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\AdvisoryReference;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Version\AffectedVersions;
use Psr\Clock\ClockInterface;

/**
 * @internal
 */
final readonly class PackagistAdvisoryNormalizer
{
    private const string REPORTED_AT_FORMAT = 'Y-m-d H:i:s';

    public function __construct(
        private ClockInterface $clock,
    ) {
    }

    /**
     * @param array<mixed> $record one entry of the list Packagist files under a package
     */
    public function normalize(array $record, PackageUrl $package): Advisory
    {
        $affectedVersions = $this->readAffectedVersions($record);

        return new Advisory(
            advisoryId: $this->readString($record, 'advisoryId'),
            package: $package,
            title: $this->readString($record, 'title'),
            link: $this->safeUrl($this->readString($record, 'link')),
            cve: $this->readString($record, 'cve'),
            affectedVersions: $affectedVersions,
            reportedAt: $this->readReportedAt($record),
            severity: Severity::fromFeedValue($this->readString($record, 'severity')),
            references: $this->readReferences($record),
            firstPatchedVersion: $this->lowestVersion($affectedVersions->fixedVersions()),
        );
    }

    /**
     * @param array<mixed> $record
     */
    private function readString(array $record, string $field): string
    {
        $value = $record[$field] ?? null;

        return is_string($value) ? $value : '';
    }

    private function safeUrl(string $url): string
    {
        $url = trim($url);

        return Advisory::isSafeLink($url) ? $url : '';
    }

    /**
     * @param array<mixed> $record
     */
    private function readReportedAt(array $record): \DateTimeImmutable
    {
        $reportedAt = trim($this->readString($record, 'reportedAt'));

        if ($reportedAt === '') {
            return $this->clock->now();
        }

        $parsed = \DateTimeImmutable::createFromFormat(
            '!' . self::REPORTED_AT_FORMAT,
            $reportedAt,
            new \DateTimeZone('UTC'),
        );

        if ($parsed instanceof \DateTimeImmutable) {
            return $parsed;
        }

        try {
            return new \DateTimeImmutable($reportedAt, new \DateTimeZone('UTC'));
        } catch (\DateMalformedStringException) {
            return $this->clock->now();
        }
    }

    /**
     * @param array<mixed> $record
     * @return list<AdvisoryReference>
     */
    private function readReferences(array $record): array
    {
        $references = [];
        $sources = is_array($record['sources'] ?? null) ? $record['sources'] : [];

        foreach ($sources as $source) {
            if (is_array($source)) {
                $references = $this->withReference(
                    $references,
                    $this->readString($source, 'name'),
                    $this->readString($source, 'remoteId'),
                );
            }
        }

        // The record's own source is normally the first entry of 'sources'.
        $references = $this->withReference(
            $references,
            $this->readString($record, 'source'),
            $this->readString($record, 'remoteId'),
        );

        return array_values($references);
    }

    /**
     * @param array<string, AdvisoryReference> $references
     * @return array<string, AdvisoryReference>
     */
    private function withReference(array $references, string $name, string $remoteId): array
    {
        if ($name !== '' && $remoteId !== '') {
            $references[$name . '|' . $remoteId] ??= new AdvisoryReference($name, $remoteId);
        }

        return $references;
    }

    /**
     * @param array<mixed> $record
     */
    private function readAffectedVersions(array $record): AffectedVersions
    {
        try {
            return AffectedVersions::fromComposerConstraint($this->readString($record, 'affectedVersions'));
        } catch (\InvalidArgumentException) {
            // If the syntax outside the modelled subset states nothing usable, report advisory as undetermined.
            return new AffectedVersions();
        }
    }

    /**
     * @param list<string> $versions
     */
    private function lowestVersion(array $versions): string
    {
        $lowest = '';

        foreach ($versions as $version) {
            $version = preg_replace('/\Av(?=\d)/', '', $version) ?? $version;

            if ($lowest === '' || version_compare($version, $lowest, '<')) {
                $lowest = $version;
            }
        }

        return $lowest;
    }
}
