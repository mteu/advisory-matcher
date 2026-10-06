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

final readonly class Advisory
{
    /**
     * @param list<AdvisoryReference> $references every feed that reported this
     * @param string $firstPatchedVersion lowest fix on any branch, for display only; see AdvisoryMatcher::fixedVersionFor()
     */
    public function __construct(
        public string $advisoryId,
        public string $packageName,
        public Ecosystem $ecosystem,
        public string $title,
        public string $link,
        public string $cve,
        public AffectedVersions $affectedVersions,
        public \DateTimeImmutable $reportedAt,
        public Severity $severity,
        public array $references,
        public string $firstPatchedVersion = '',
    ) {
        if (trim($packageName) === '') {
            throw new \InvalidArgumentException('An advisory has to name the package it is filed under.');
        }

        if (!self::isSafeLink($link)) {
            throw new \InvalidArgumentException('An advisory link has to be an http(s) URL or empty.');
        }

        if (!array_is_list($references)) {
            throw new \InvalidArgumentException('An advisory\'s references have to be a list.');
        }

        foreach ($references as $reference) {
            if (!$reference instanceof AdvisoryReference) {
                throw new \InvalidArgumentException('An advisory reference has to be an AdvisoryReference.');
            }
        }
    }

    public static function isSafeLink(string $link): bool
    {
        if ($link === '') {
            return true;
        }

        $scheme = parse_url($link, PHP_URL_SCHEME);

        return is_string($scheme) && in_array(strtolower($scheme), ['http', 'https'], true);
    }

    public function getFingerprint(): string
    {
        return AdvisoryFingerprint::canonical($this);
    }

    public function hasCve(): bool
    {
        return $this->cve !== '';
    }

    public function hasRemediation(): bool
    {
        return $this->firstPatchedVersion !== '';
    }
}
