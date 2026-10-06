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
use mteu\AdvisoryMatcher\Advisory\AdvisoryReference;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Version\AffectedVersions;

/**
 * @phpstan-type EncodedReference array{name: string, remoteId: string}
 * @phpstan-type EncodedAdvisory array{
 *     advisoryId: string,
 *     packageName: string,
 *     ecosystem: string,
 *     title: string,
 *     link: string,
 *     cve: string,
 *     affectedVersions: string,
 *     reportedAt: string,
 *     severity: string,
 *     references: list<EncodedReference>,
 *     firstPatchedVersion: string,
 * }
 * @internal
 */
final readonly class CachedAnswerCodec
{
    private const array STRING_FIELDS = [
        'advisoryId', 'packageName', 'ecosystem', 'title', 'link', 'cve', 'affectedVersions',
        'reportedAt', 'severity', 'firstPatchedVersion',
    ];

    /**
     * @param list<Advisory> $advisories
     * @return list<EncodedAdvisory>
     */
    public function encode(array $advisories): array
    {
        return array_map($this->encodeAdvisory(...), $advisories);
    }

    /**
     * @return list<Advisory>
     * @throws UnreadableCacheEntry
     */
    public function decode(mixed $entry): array
    {
        if (!is_array($entry) || !array_is_list($entry)) {
            throw UnreadableCacheEntry::because('no advisory list');
        }

        return array_map($this->decodeAdvisory(...), $entry);
    }

    /**
     * @return EncodedAdvisory
     */
    private function encodeAdvisory(Advisory $advisory): array
    {
        return [
            'advisoryId' => $advisory->advisoryId,
            'packageName' => $advisory->packageName,
            'ecosystem' => $advisory->ecosystem->value,
            'title' => $advisory->title,
            'link' => $advisory->link,
            'cve' => $advisory->cve,
            'affectedVersions' => $advisory->affectedVersions->toComposerConstraint(),
            'reportedAt' => $advisory->reportedAt->format(\DateTimeInterface::ATOM),
            'severity' => $advisory->severity->value,
            'references' => array_map(
                static fn (AdvisoryReference $reference): array => [
                    'name' => $reference->name,
                    'remoteId' => $reference->remoteId,
                ],
                $advisory->references,
            ),
            'firstPatchedVersion' => $advisory->firstPatchedVersion,
        ];
    }

    /**
     * @throws UnreadableCacheEntry
     */
    private function decodeAdvisory(mixed $record): Advisory
    {
        if (!is_array($record)) {
            throw UnreadableCacheEntry::because('an advisory is not a record');
        }

        $fields = [];

        foreach (self::STRING_FIELDS as $field) {
            $value = $record[$field] ?? null;

            if (!is_string($value)) {
                throw UnreadableCacheEntry::because(sprintf('an advisory has no "%s"', $field));
            }

            $fields[$field] = $value;
        }

        $ecosystem = Ecosystem::tryFrom($fields['ecosystem']);
        $severity = Severity::tryFrom($fields['severity']);
        $reportedAt = \DateTimeImmutable::createFromFormat(\DateTimeInterface::ATOM, $fields['reportedAt']);

        if ($ecosystem === null || $severity === null || $reportedAt === false) {
            throw UnreadableCacheEntry::because('an advisory has no readable ecosystem, severity or date');
        }

        try {
            return new Advisory(
                advisoryId: $fields['advisoryId'],
                packageName: $fields['packageName'],
                ecosystem: $ecosystem,
                title: $fields['title'],
                link: $fields['link'],
                cve: $fields['cve'],
                affectedVersions: AffectedVersions::fromComposerConstraint($fields['affectedVersions']),
                reportedAt: $reportedAt,
                severity: $severity,
                references: $this->decodeReferences($record['references'] ?? null),
                firstPatchedVersion: $fields['firstPatchedVersion'],
            );
        } catch (\InvalidArgumentException $exception) {
            throw UnreadableCacheEntry::becauseOf($exception);
        }
    }

    /**
     * @return list<AdvisoryReference>
     * @throws UnreadableCacheEntry
     */
    private function decodeReferences(mixed $references): array
    {
        if (!is_array($references)) {
            throw UnreadableCacheEntry::because('an advisory has no reference list');
        }

        $decoded = [];

        foreach ($references as $reference) {
            if (!is_array($reference) || !is_string($reference['name'] ?? null) || !is_string($reference['remoteId'] ?? null)) {
                throw UnreadableCacheEntry::because('an advisory reference is malformed');
            }

            $decoded[] = new AdvisoryReference($reference['name'], $reference['remoteId']);
        }

        return $decoded;
    }
}
