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

namespace mteu\AdvisoryMatcher\Tests\Unit\Clock;

use Psr\Clock\ClockInterface;

final readonly class FrozenClock implements ClockInterface
{
    public function __construct(
        private \DateTimeImmutable $now,
    ) {
    }

    public static function at(string $time): self
    {
        return new self(new \DateTimeImmutable($time));
    }

    public function now(): \DateTimeImmutable
    {
        return $this->now;
    }
}
