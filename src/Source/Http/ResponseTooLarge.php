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

namespace mteu\AdvisoryMatcher\Source\Http;

/**
 * @internal
 */
final class ResponseTooLarge extends \Exception
{
    public static function beyond(int $maxBytes): self
    {
        return new self(sprintf('The response exceeds the %d MiB cap.', intdiv($maxBytes, 1_048_576)));
    }
}
