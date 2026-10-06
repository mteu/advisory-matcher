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
final class ResponseBodyUnreadable extends \Exception
{
    public static function because(\RuntimeException $streamFailure): self
    {
        return new self(
            'The response body could not be read: ' . $streamFailure->getMessage(),
            previous: $streamFailure,
        );
    }
}
