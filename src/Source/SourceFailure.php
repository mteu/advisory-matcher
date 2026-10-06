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

use mteu\AdvisoryMatcher\Package\Ecosystem;

final readonly class SourceFailure
{
    /**
     * @param string $detail for logs only; match on $reason
     * @param int|null $retryAfterSeconds the feed's Retry-After
     */
    public function __construct(
        public string $sourceName,
        public Ecosystem $ecosystem,
        public FailureReason $reason,
        public string $detail,
        public ?int $retryAfterSeconds = null,
    ) {
        if (trim($sourceName) === '') {
            throw new \InvalidArgumentException('A failure has to name the source it came from.');
        }

        if ($retryAfterSeconds !== null && $retryAfterSeconds < 0) {
            throw new \InvalidArgumentException('A retry-after delay cannot be negative.');
        }
    }
}
