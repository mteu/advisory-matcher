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

use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Version\AffectedVersions;
use mteu\AdvisoryMatcher\Version\LenientVersionMatcher;
use mteu\AdvisoryMatcher\Version\VersionConstraintMatcher;

final readonly class AdvisoryMatcher
{
    public function __construct(
        private VersionConstraintMatcher $strict = new VersionConstraintMatcher(),
        private LenientVersionMatcher $lenient = new LenientVersionMatcher(),
    ) {
    }

    public function match(Advisory $advisory, string $version): MatchResult
    {
        return $this->matchVersions($advisory->affectedVersions, $version, $advisory->ecosystem);
    }

    public function fixedVersionFor(Advisory $advisory, string $installedVersion): string
    {
        foreach ($advisory->affectedVersions->ranges as $range) {
            $branch = new AffectedVersions([$range]);

            if ($this->matchVersions($branch, $installedVersion, $advisory->ecosystem) === MatchResult::Affected) {
                return $range->before;
            }
        }

        return '';
    }

    /**
     * @param iterable<Advisory> $advisories
     */
    public function matchAll(iterable $advisories, string $version): AdvisoryMatches
    {
        $sorted = ['affected' => [], 'not_affected' => [], 'undetermined' => []];

        foreach ($advisories as $advisory) {
            $sorted[$this->match($advisory, $version)->value][] = $advisory;
        }

        return new AdvisoryMatches(
            affected: $sorted['affected'],
            notAffected: $sorted['not_affected'],
            undetermined: $sorted['undetermined'],
        );
    }

    private function matchVersions(AffectedVersions $affected, string $version, Ecosystem $ecosystem): MatchResult
    {
        if ($affected->isEmpty() || !$this->isComparableVersion($version)) {
            return MatchResult::Undetermined;
        }

        try {
            return $this->resultOf($this->strict->satisfies($version, $affected->toComposerConstraint()));
        } catch (\UnexpectedValueException) {
            // Only Composer, PHP and platform versions are close enough to Composer's rules for the lenient fallback.
        }

        if (!in_array($ecosystem, [Ecosystem::Composer, Ecosystem::Php, Ecosystem::Platform], true)
            || !$this->lenient->canCompare($version, $affected)
        ) {
            return MatchResult::Undetermined;
        }

        return $this->resultOf($this->lenient->satisfies($version, $affected));
    }

    private function isComparableVersion(string $version): bool
    {
        return preg_match('/^v?\d/i', trim($version)) === 1;
    }

    private function resultOf(bool $satisfied): MatchResult
    {
        return $satisfied ? MatchResult::Affected : MatchResult::NotAffected;
    }
}
