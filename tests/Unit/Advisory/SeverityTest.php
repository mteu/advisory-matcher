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

namespace mteu\AdvisoryMatcher\Tests\Unit\Advisory;

use mteu\AdvisoryMatcher\Advisory\Severity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Severity::class)]
final class SeverityTest extends TestCase
{
    #[Test]
    public function ordersSeveritiesFromLowToCritical(): void
    {
        self::assertLessThan(Severity::Medium->getPriority(), Severity::Low->getPriority());
        self::assertLessThan(Severity::High->getPriority(), Severity::Medium->getPriority());
        self::assertLessThan(Severity::Critical->getPriority(), Severity::High->getPriority());
    }

    #[Test]
    public function ranksAnUnknownSeverityWithHigh(): void
    {
        self::assertSame(Severity::High->getPriority(), Severity::Unknown->getPriority());
    }

    #[Test]
    #[DataProvider('severityThresholdProvider')]
    public function reportsWhetherSeverityMeetsThreshold(
        Severity $severity,
        Severity $threshold,
        bool $expected,
    ): void {
        self::assertSame($expected, $severity->isAtLeast($threshold));
    }

    #[Test]
    #[DataProvider('feedValueProvider')]
    public function resolvesAFeedsOwnSeverityLabel(string $label, Severity $expected): void
    {
        self::assertSame($expected, Severity::fromFeedValue($label));
    }

    /**
     * @return iterable<string, array{string, Severity}>
     */
    public static function feedValueProvider(): iterable
    {
        yield 'low' => ['low', Severity::Low];
        yield 'medium' => ['medium', Severity::Medium];
        yield 'high' => ['high', Severity::High];
        yield 'critical' => ['critical', Severity::Critical];

        // GitHub and OSV spell the middle band this way.
        yield 'moderate is the middle band' => ['moderate', Severity::Medium];
        yield 'info is the lowest band' => ['info', Severity::Low];
        yield 'informational is the lowest band' => ['informational', Severity::Low];
        yield 'CVSS none is the lowest band' => ['none', Severity::Low];

        yield 'uppercase is normalised' => ['CRITICAL', Severity::Critical];
        yield 'mixed case is normalised' => ['Moderate', Severity::Medium];
        yield 'surrounding whitespace is trimmed' => ['  high  ', Severity::High];
    }

    #[Test]
    #[DataProvider('unrecognisedLabelProvider')]
    public function treatsAMissingOrUnrecognisedLabelAsUnknown(string $label): void
    {
        self::assertSame(Severity::Unknown, Severity::fromFeedValue($label));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unrecognisedLabelProvider(): iterable
    {
        yield 'empty string' => [''];
        yield 'whitespace only' => ['   '];
        yield 'unknown' => ['unknown'];
        yield 'invented label' => ['catastrophic'];
    }

    #[Test]
    #[DataProvider('cvssScoreProvider')]
    public function placesACvssScoreInItsBand(float $score, Severity $expected): void
    {
        self::assertSame($expected, Severity::fromCvssScore($score));
    }

    /**
     * @return iterable<string, array{float, Severity}>
     */
    public static function cvssScoreProvider(): iterable
    {
        yield 'critical lower bound' => [9.0, Severity::Critical];
        yield 'critical maximum' => [10.0, Severity::Critical];
        yield 'high lower bound' => [7.0, Severity::High];
        yield 'high upper edge' => [8.9, Severity::High];
        yield 'medium lower bound' => [4.0, Severity::Medium];
        yield 'medium upper edge' => [6.9, Severity::Medium];
        yield 'low upper edge' => [3.9, Severity::Low];
        yield 'zero' => [0.0, Severity::Low];
    }

    /**
     * @return iterable<string, array{Severity, Severity, bool}>
     */
    public static function severityThresholdProvider(): iterable
    {
        yield 'equal severity meets threshold' => [Severity::High, Severity::High, true];
        yield 'higher severity meets threshold' => [Severity::Critical, Severity::High, true];
        yield 'lower severity misses threshold' => [Severity::Medium, Severity::High, false];
        yield 'lowest severity misses highest threshold' => [Severity::Low, Severity::Critical, false];
        yield 'lowest severity meets lowest threshold' => [Severity::Low, Severity::Low, true];
        yield 'unknown meets a high threshold' => [Severity::Unknown, Severity::High, true];
        yield 'unknown misses a critical threshold' => [Severity::Unknown, Severity::Critical, false];
    }
}
