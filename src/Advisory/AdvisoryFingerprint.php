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

namespace mteu\AdvisoryMatcher\Advisory;

use mteu\AdvisoryMatcher\Package\PackageUrl;

final class AdvisoryFingerprint
{
    public static function canonical(Advisory $advisory): string
    {
        return self::identitiesOf($advisory)[0];
    }

    /**
     * @return non-empty-list<string>
     */
    public static function identitiesOf(Advisory $advisory): array
    {
        $identities = [];
        $package = self::packageKeyOf($advisory->package);

        $cve = strtoupper(trim($advisory->cve));
        if ($cve !== '') {
            $identities[] = $package . '|cve|' . $cve;
        }

        foreach (self::githubAdvisoryIds($advisory) as $githubAdvisoryId) {
            $identities[] = $package . '|ghsa|' . $githubAdvisoryId;
        }

        $nativeId = trim($advisory->advisoryId);
        if ($nativeId !== '') {
            $identities[] = $package . '|id|' . $nativeId;
        }

        if ($identities === []) {
            // An empty id would merge all unnamed advisories of a package, so key on the content.
            $identities[] = $package . '|hash|' . substr(
                hash('sha256', $advisory->title . '|' . $advisory->affectedVersions->toComposerConstraint()),
                0,
                32,
            );
        }

        return $identities;
    }

    /**
     * The identities that ids read from outside, such as a VEX document, answer to.
     *
     * @param list<string> $advisoryIds as written
     * @return list<string>
     */
    public static function identitiesNaming(PackageUrl $package, array $advisoryIds): array
    {
        $prefix = self::packageKeyOf($package) . '|';
        $identities = [];

        foreach ($advisoryIds as $advisoryId) {
            $id = trim($advisoryId);

            // A pipe would corrupt the key.
            if ($id === '' || str_contains($id, '|')) {
                continue;
            }

            $upperCased = strtoupper($id);
            $identities[] = $prefix . match (true) {
                str_starts_with($upperCased, 'CVE-') => 'cve|' . $upperCased,
                str_starts_with($upperCased, 'GHSA-') => 'ghsa|' . $upperCased,
                default => 'id|' . $id,
            };
        }

        return array_values(array_unique($identities));
    }

    private static function packageKeyOf(PackageUrl $package): string
    {
        return $package->ecosystem()->value . '|' . $package->packageName();
    }

    /**
     * @return list<string>
     */
    private static function githubAdvisoryIds(Advisory $advisory): array
    {
        $candidates = [$advisory->advisoryId];

        foreach ($advisory->references as $reference) {
            $candidates[] = $reference->remoteId;
        }

        $githubAdvisoryIds = [];

        foreach ($candidates as $candidate) {
            $candidate = strtoupper(trim($candidate));

            if (str_starts_with($candidate, 'OSV-')) {
                $candidate = substr($candidate, 4);
            }

            if (str_starts_with($candidate, 'GHSA-') && !in_array($candidate, $githubAdvisoryIds, true)) {
                $githubAdvisoryIds[] = $candidate;
            }
        }

        return $githubAdvisoryIds;
    }
}
