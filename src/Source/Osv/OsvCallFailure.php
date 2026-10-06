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

namespace mteu\AdvisoryMatcher\Source\Osv;

use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\SourceFailure;

/**
 * @internal
 */
final readonly class OsvCallFailure
{
    public function __construct(
        public FailureReason $reason,
        public string $detail,
        public ?int $retryAfterSeconds = null,
    ) {
    }

    public function toSourceFailure(string $sourceName, Ecosystem $ecosystem, string $detail): SourceFailure
    {
        return new SourceFailure(
            sourceName: $sourceName,
            ecosystem: $ecosystem,
            reason: $this->reason,
            detail: $detail,
            retryAfterSeconds: $this->retryAfterSeconds,
        );
    }
}
