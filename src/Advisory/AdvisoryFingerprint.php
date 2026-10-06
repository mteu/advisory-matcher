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
        $package = $advisory->ecosystem->value . '|' . $advisory->packageName;

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
            // Nothing names this advisory. Falling back to the empty id would collapse every of those advisories of a package
            // into one, so derive a stable key from what the record actually says instead.
            $identities[] = $package . '|hash|' . substr(
                hash('sha256', $advisory->title . '|' . $advisory->affectedVersions->toComposerConstraint()),
                0,
                32,
            );
        }

        return $identities;
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
