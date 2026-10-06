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

namespace mteu\AdvisoryMatcher\Package;

enum Ecosystem: string
{
    case Composer = 'composer';
    case Npm = 'npm';
    case Php = 'php';
    case Unknown = 'unknown';

    public static function fromPackageUrlType(string $type): self
    {
        return match (strtolower(trim($type))) {
            'composer', 'packagist' => self::Composer,
            'npm', 'node' => self::Npm,
            'php' => self::Php,
            default => self::Unknown,
        };
    }

    public function getDisplayName(): string
    {
        return match ($this) {
            self::Composer => 'Composer',
            self::Npm => 'npm',
            self::Php => 'PHP',
            self::Unknown => 'Unknown',
        };
    }
}
