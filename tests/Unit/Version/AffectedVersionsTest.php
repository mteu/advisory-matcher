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

use mteu\AdvisoryMatcher\Version\AffectedVersions;
use mteu\AdvisoryMatcher\Version\VersionRange;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(AffectedVersions::class)]
final class AffectedVersionsTest extends TestCase
{
    #[Test]
    #[DataProvider('constraintsAndTheirRanges')]
    public function readsAComposerConstraintIntoRanges(string $constraint, AffectedVersions $expected): void
    {
        self::assertEquals($expected, AffectedVersions::fromComposerConstraint($constraint));
    }

    /**
     * @return iterable<string, array{string, AffectedVersions}>
     */
    public static function constraintsAndTheirRanges(): iterable
    {
        yield 'nothing' => ['', new AffectedVersions()];
        yield 'every version' => ['*', new AffectedVersions([new VersionRange()])];
        yield 'a comma-separated range' => [
            '>=1.0.0,<1.2.0',
            new AffectedVersions([new VersionRange(from: '1.0.0', before: '1.2.0')]),
        ];
        yield 'a space-separated range' => [
            '>= 1.0 <2.0',
            new AffectedVersions([new VersionRange(from: '1.0', before: '2.0')]),
        ];
        yield 'single and double bars' => [
            '>1.0|<=0.5 || 3.0',
            new AffectedVersions([
                new VersionRange(after: '1.0'),
                new VersionRange(through: '0.5'),
                VersionRange::exactly('3.0'),
            ]),
        ];
        yield 'equals signs mean one exact version' => [
            '=1.0 || ==2.0',
            new AffectedVersions([VersionRange::exactly('1.0'), VersionRange::exactly('2.0')]),
        ];
    }

    #[Test]
    #[DataProvider('constraintsOutsideTheModel')]
    public function refusesSyntaxOutsideTheModel(string $constraint): void
    {
        $this->expectException(\InvalidArgumentException::class);

        AffectedVersions::fromComposerConstraint($constraint);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function constraintsOutsideTheModel(): iterable
    {
        yield 'caret' => ['^1.2'];
        yield 'tilde' => ['~1.4'];
        yield 'wildcard' => ['1.2.*'];
        yield 'not equal' => ['!=1.0'];
        yield 'an operator without a version' => ['>='];
        yield 'two lower bounds in one range' => ['>=1.0,>=1.1'];
        yield 'a null byte' => [">=1.0\0.0"];
        yield 'only separators' => [',,|,'];
    }

    #[Test]
    #[DataProvider('constraintsInRenderedForm')]
    public function survivesARoundTripThroughItsRenderedConstraint(string $constraint): void
    {
        $affected = AffectedVersions::fromComposerConstraint($constraint);

        self::assertEquals($affected, AffectedVersions::fromComposerConstraint($affected->toComposerConstraint()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function constraintsInRenderedForm(): iterable
    {
        yield 'nothing' => [''];
        yield 'every version' => ['*'];
        yield 'two branches' => ['>=1.0.0,<1.2.3|>=2.0, <2.0.5'];
        yield 'bounds of every kind' => ['>1.0,<=1.5 || 2.0'];
    }

    #[Test]
    public function keepsEachRangeOnce(): void
    {
        $affected = AffectedVersions::fromComposerConstraint('>=1.0,<1.2 || >=1.0, <1.2');

        self::assertSame('>=1.0,<1.2', $affected->toComposerConstraint());
    }

    #[Test]
    public function unionHoldsTheRangesOfBothWithoutRepeats(): void
    {
        $left = AffectedVersions::fromComposerConstraint('>=1.0,<1.2');
        $right = AffectedVersions::fromComposerConstraint('>=1.0,<1.2 || >=2.0,<2.1');

        self::assertSame('>=1.0,<1.2 || >=2.0,<2.1', $left->union($right)->toComposerConstraint());
    }

    #[Test]
    public function listsTheFixOfEveryRangeThatHasOne(): void
    {
        $affected = AffectedVersions::fromComposerConstraint('>=1.0,<1.2 || <=1.5 || >=2.0,<2.1 || >=3.0');

        self::assertSame(['1.2', '2.1'], $affected->fixedVersions());
    }

    #[Test]
    public function isEmptyOnlyWhenItStatesNoRange(): void
    {
        self::assertTrue((new AffectedVersions())->isEmpty());
        self::assertFalse(AffectedVersions::fromComposerConstraint('*')->isEmpty());
    }
}
