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

namespace mteu\AdvisoryMatcher\Source;

enum FailureReason: string
{
    /** Not reached, or answered with a 5xx. */
    case Unreachable = 'unreachable';

    case Timeout = 'timeout';

    /** A 4xx that is not rate limiting. */
    case Rejected = 'rejected';

    case RateLimited = 'rate_limited';

    /** A 2xx whose body is not what the feed documents. */
    case Unparseable = 'unparseable';

    /** The source threw, which is a defect. Filed by CompositeAdvisorySource. */
    case Broken = 'broken';

    public function isTransient(): bool
    {
        return match ($this) {
            self::Unreachable, self::Timeout, self::RateLimited => true,
            self::Rejected, self::Unparseable, self::Broken => false,
        };
    }
}
