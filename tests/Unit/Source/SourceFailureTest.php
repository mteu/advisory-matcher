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

namespace mteu\AdvisoryMatcher\Tests\Unit\Source;

use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(SourceFailure::class)]
#[CoversClass(FailureReason::class)]
final class SourceFailureTest extends TestCase
{
    #[Test]
    public function rejectsAFailureThatNamesNoSource(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new SourceFailure(
            sourceName: '  ',
            ecosystem: Ecosystem::Composer,
            reason: FailureReason::Timeout,
            detail: 'timed out',
        );
    }

    #[Test]
    public function rejectsANegativeRetryDelay(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new SourceFailure(
            sourceName: 'OSV',
            ecosystem: Ecosystem::Npm,
            reason: FailureReason::RateLimited,
            detail: '429',
            retryAfterSeconds: -1,
        );
    }

    #[Test]
    public function aRetryDelayIsOptional(): void
    {
        $failure = new SourceFailure(
            sourceName: 'Packagist',
            ecosystem: Ecosystem::Composer,
            reason: FailureReason::Unreachable,
            detail: 'connection refused',
        );

        self::assertNull($failure->retryAfterSeconds);
    }

    #[Test]
    public function zeroIsAValidRetryDelay(): void
    {
        $failure = new SourceFailure(
            sourceName: 'OSV',
            ecosystem: Ecosystem::Npm,
            reason: FailureReason::RateLimited,
            detail: 'Retry-After: 0',
            retryAfterSeconds: 0,
        );

        self::assertSame(0, $failure->retryAfterSeconds);
    }

    #[Test]
    #[DataProvider('reasonProvider')]
    public function reportsWhetherRetryingCouldHelp(FailureReason $reason, bool $expected): void
    {
        self::assertSame($expected, $reason->isTransient());
    }

    /**
     * @return iterable<string, array{FailureReason, bool}>
     */
    public static function reasonProvider(): iterable
    {
        yield 'unreachable' => [FailureReason::Unreachable, true];
        yield 'timeout' => [FailureReason::Timeout, true];
        yield 'rate limited' => [FailureReason::RateLimited, true];
        yield 'rejected' => [FailureReason::Rejected, false];
        yield 'unparseable' => [FailureReason::Unparseable, false];
        yield 'broken' => [FailureReason::Broken, false];
    }
}
