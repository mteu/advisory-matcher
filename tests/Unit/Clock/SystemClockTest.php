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

use mteu\AdvisoryMatcher\Clock\SystemClock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;

#[CoversClass(SystemClock::class)]
final class SystemClockTest extends TestCase
{
    #[Test]
    public function isAPsr20ClockSoAnyConsumerClockCanTakeItsPlace(): void
    {
        self::assertInstanceOf(ClockInterface::class, new SystemClock());
    }

    #[Test]
    public function tellsTheCurrentTime(): void
    {
        $before = new \DateTimeImmutable();
        $now = (new SystemClock())->now();
        $after = new \DateTimeImmutable();

        self::assertGreaterThanOrEqual($before, $now);
        self::assertLessThanOrEqual($after, $now);
    }
}
