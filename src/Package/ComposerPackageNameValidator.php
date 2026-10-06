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

/**
 * @internal
 */
final readonly class ComposerPackageNameValidator
{
    private const string PATTERN = '{^[a-z0-9](?:[_.-]?[a-z0-9]+)*/[a-z0-9](?:(?:[_.]|-{1,2})?[a-z0-9]+)*$}iD';

    public function isValid(string $packageName): bool
    {
        return preg_match(self::PATTERN, $packageName) === 1;
    }
}
