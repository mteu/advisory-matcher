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
use mteu\AdvisoryMatcher\Advisory\AdvisoryFingerprint;
use mteu\AdvisoryMatcher\Advisory\AdvisoryReference;
use mteu\AdvisoryMatcher\Advisory\Severity;

final readonly class AdvisoryDeduplicator
{
    public function deduplicate(AdvisoryBatch $batch): AdvisoryBatch
    {
        return new AdvisoryBatch(
            answeredFor: array_map(
                fn (AnsweredPackage $answer): AnsweredPackage => new AnsweredPackage(
                    $answer->package,
                    $this->foldDuplicates($answer->advisories),
                ),
                $batch->answeredFor,
            ),
            failures: $batch->failures,
        );
    }

    /**
     * Matches on every identity of an advisory, not only the canonical one.
     * OSV files a finding as `OSV-GHSA-…` and Packagist as `PKSA-…`.
     *
     * @param list<Advisory> $advisories
     * @return list<Advisory>
     */
    private function foldDuplicates(array $advisories): array
    {
        $folded = [];

        /** @var array<string, int> $positions */
        $positions = [];

        foreach ($advisories as $advisory) {
            $identities = AdvisoryFingerprint::identitiesOf($advisory);
            $position = $this->positionOfAny($identities, $positions);

            if ($position === -1) {
                $folded[] = $advisory;
                $position = count($folded) - 1;
            } else {
                $folded[$position] = $this->merge($folded[$position], $advisory);
            }

            // So a later report naming only the CVE still finds an entry first matched by its GHSA id.
            foreach ($identities as $identity) {
                $positions[$identity] ??= $position;
            }
        }

        return array_values($folded);
    }

    /**
     * @param list<string> $identities
     * @param array<string, int> $positions
     */
    private function positionOfAny(array $identities, array $positions): int
    {
        foreach ($identities as $identity) {
            if (array_key_exists($identity, $positions)) {
                return $positions[$identity];
            }
        }

        return -1;
    }

    private function merge(Advisory $held, Advisory $other): Advisory
    {
        return new Advisory(
            advisoryId: $held->advisoryId,
            package: $held->package,
            title: $held->title,
            link: $held->link,
            cve: $held->hasCve() ? $held->cve : $other->cve,
            affectedVersions: $held->affectedVersions->union($other->affectedVersions),
            reportedAt: $held->reportedAt,
            severity: $this->moreAlarmingSeverity($held->severity, $other->severity),
            references: $this->unionReferences($held->references, $other->references),
            firstPatchedVersion: $this->nearestPatchedVersion($held->firstPatchedVersion, $other->firstPatchedVersion),
        );
    }

    private function moreAlarmingSeverity(Severity $held, Severity $other): Severity
    {
        if ($other->getPriority() !== $held->getPriority()) {
            return $other->getPriority() > $held->getPriority() ? $other : $held;
        }

        return $held === Severity::Unknown ? $other : $held;
    }

    private function nearestPatchedVersion(string $left, string $right): string
    {
        if ($left === '' || $right === '') {
            return $left !== '' ? $left : $right;
        }

        return version_compare($left, $right, '<') ? $left : $right;
    }

    /**
     * @param list<AdvisoryReference> $left
     * @param list<AdvisoryReference> $right
     * @return list<AdvisoryReference>
     */
    private function unionReferences(array $left, array $right): array
    {
        $references = [];

        foreach ([...$left, ...$right] as $reference) {
            $references[$reference->name . '|' . $reference->remoteId] = $reference;
        }

        return array_values($references);
    }
}
