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

namespace mteu\AdvisoryMatcher\Tests\Unit\Version;

use mteu\AdvisoryMatcher\Version\VersionRange;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(VersionRange::class)]
final class VersionRangeTest extends TestCase
{
    #[Test]
    #[DataProvider('rangesAndTheirConstraint')]
    public function rendersItselfAsAComposerConstraint(VersionRange $range, string $expected): void
    {
        self::assertSame($expected, $range->toComposerConstraint());
    }

    /**
     * @return iterable<string, array{VersionRange, string}>
     */
    public static function rangesAndTheirConstraint(): iterable
    {
        yield 'every version' => [new VersionRange(), '*'];
        yield 'inclusive lower and exclusive upper' => [new VersionRange(from: '1.0.0', before: '1.2.0'), '>=1.0.0,<1.2.0'];
        yield 'exclusive lower and inclusive upper' => [new VersionRange(after: '1.0.0', through: '1.2.0'), '>1.0.0,<=1.2.0'];
        yield 'upper bound only' => [new VersionRange(before: '2.0.0'), '<2.0.0'];
        yield 'one exact version' => [VersionRange::exactly('1.4.2'), '1.4.2'];
    }

    #[Test]
    public function listsOnlyTheBoundsItHas(): void
    {
        self::assertSame(['1.0.0', '1.2.0'], (new VersionRange(from: '1.0.0', before: '1.2.0'))->bounds());
        self::assertSame([], (new VersionRange())->bounds());
    }

    #[Test]
    #[DataProvider('invalidRanges')]
    public function refusesARangeThatCannotBeRenderedSafely(\Closure $build): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $build();
    }

    /**
     * @return iterable<string, array{\Closure(): VersionRange}>
     */
    public static function invalidRanges(): iterable
    {
        yield 'two lower bounds' => [static fn (): VersionRange => new VersionRange(from: '1.0', after: '1.0')];
        yield 'two upper bounds' => [static fn (): VersionRange => new VersionRange(before: '2.0', through: '2.0')];
        yield 'an operator inside a bound' => [static fn (): VersionRange => new VersionRange(before: '2.0,>=0')];
        yield 'an or inside a bound' => [static fn (): VersionRange => new VersionRange(from: '1.0|*')];
        yield 'whitespace inside a bound' => [static fn (): VersionRange => new VersionRange(from: '1.0 2.0')];
        yield 'a null byte' => [static fn (): VersionRange => new VersionRange(from: "1.0\0")];
        yield 'a wildcard' => [static fn (): VersionRange => new VersionRange(from: '1.2.*')];
    }
}
