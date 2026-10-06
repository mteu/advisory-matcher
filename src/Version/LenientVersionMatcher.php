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

namespace mteu\AdvisoryMatcher\Version;

/**
 * @internal
 */
final readonly class LenientVersionMatcher
{
    private const string VERSION_PATTERN = '/^v?\d[0-9a-z.+~_-]*$/i';

    public function canCompare(string $version, AffectedVersions $affected): bool
    {
        if ($affected->isEmpty() || !$this->isComparable($version)) {
            return false;
        }

        foreach ($affected->ranges as $range) {
            foreach ($range->bounds() as $bound) {
                if (!$this->isComparable($bound)) {
                    return false;
                }
            }
        }

        return true;
    }

    public function satisfies(string $version, AffectedVersions $affected): bool
    {
        foreach ($affected->ranges as $range) {
            if ($this->isInRange($version, $range)) {
                return true;
            }
        }

        return false;
    }

    private function isInRange(string $version, VersionRange $range): bool
    {
        return ($range->from === '' || $this->compare($version, $range->from, '>='))
            && ($range->after === '' || $this->compare($version, $range->after, '>'))
            && ($range->before === '' || $this->compare($version, $range->before, '<'))
            && ($range->through === '' || $this->compare($version, $range->through, '<='));
    }

    /**
     * @param '>='|'>'|'<'|'<=' $operator
     */
    private function compare(string $version, string $bound, string $operator): bool
    {
        return version_compare($this->normalizeVersion($version), $this->normalizeVersion($bound), $operator);
    }

    private function isComparable(string $version): bool
    {
        return preg_match(self::VERSION_PATTERN, trim($version)) === 1;
    }
    private function normalizeVersion(string $version): string
    {
        $cleanVersion = preg_replace('/^v/', '', trim($version));
        if ($cleanVersion === null) {
            $cleanVersion = '0.0.0';
        }

        if ($cleanVersion === '') {
            return '0.0.0';
        }

        $parts = explode('.', $cleanVersion);

        while (count($parts) < 3) {
            $parts[] = '0';
        }

        while (count($parts) > 3 && end($parts) === '0') {
            array_pop($parts);
        }

        return implode('.', $parts);
    }
}
