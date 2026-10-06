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

/**
 * @internal
 */
final class UnreadableCacheEntry extends \Exception
{
    public static function because(string $reason): self
    {
        return new self('Unreadable cached advisory entry: ' . $reason);
    }

    public static function becauseOf(\InvalidArgumentException $invariantViolation): self
    {
        return new self(
            'Unreadable cached advisory entry: ' . $invariantViolation->getMessage(),
            0,
            $invariantViolation,
        );
    }
}
