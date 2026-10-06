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
use mteu\AdvisoryMatcher\Version\LenientVersionMatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(LenientVersionMatcher::class)]
final class LenientVersionMatcherTest extends TestCase
{
    private LenientVersionMatcher $matcher;

    protected function setUp(): void
    {
        $this->matcher = new LenientVersionMatcher();
    }

    #[Test]
    #[DataProvider('constraintProvider')]
    public function reportsWhetherVersionFallsInsideTheRanges(
        string $version,
        string $constraint,
        bool $expected,
    ): void {
        self::assertSame($expected, $this->matcher->satisfies($version, AffectedVersions::fromComposerConstraint($constraint)));
    }

    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function constraintProvider(): iterable
    {
        yield 'version inside a two sided range' => ['13.4.2', '>=13.0.0,<13.4.11', true];
        yield 'version on the inclusive lower bound' => ['13.0.0', '>=13.0.0,<13.4.11', true];
        yield 'version on the exclusive upper bound' => ['13.4.11', '>=13.0.0,<13.4.11', false];
        yield 'version above an inclusive upper bound' => ['13.4.12', '<=13.4.11', false];
        yield 'version on an inclusive upper bound' => ['13.4.11', '<=13.4.11', true];
        yield 'strictly greater excludes the bound itself' => ['13.0.0', '>13.0.0', false];
        yield 'strictly less excludes the bound itself' => ['13.0.0', '<13.0.0', false];

        yield 'OR joins two ranges' => ['12.4.7', '>=11.0.0,<11.5.41|>=12.0.0,<12.4.8', true];
        yield 'neither OR branch matches' => ['12.4.8', '>=11.0.0,<11.5.41|>=12.0.0,<12.4.8', false];

        yield 'bare version is equality' => ['13.0.0', '13.0.0', true];
        yield 'double equals is equality' => ['13.0.0', '==13.0.0', true];
        yield 'single equals is equality' => ['13.0.0', '=13.0.0', true];

        yield 'v prefix on the version is stripped' => ['v13.4.2', '>=13.0.0,<13.4.11', true];
        yield 'v prefix in the constraint is stripped' => ['13.4.2', '>=v13.0.0,<v13.4.11', true];
        yield 'two part version is padded to three' => ['v1.2', '>=1.0.0,<2.0.0', true];
        yield 'trailing zero segment compares equal' => ['13.0.0.0', '13.0.0', true];

        yield 'empty constraint is never a match' => ['13.4.2', '', false];
        yield 'blank constraint is never a match' => ['13.4.2', '   ', false];
        yield 'empty version falls back to zero' => ['', '>=13.0.0', false];
        yield 'empty version matches a zero bound' => ['', '>=0.0.0', true];
    }

    #[Test]
    #[DataProvider('composerRejectedInputProvider')]
    public function comparesVersionsComposerCannotParse(
        string $version,
        string $constraint,
        bool $expected,
    ): void {
        self::assertSame($expected, $this->matcher->satisfies($version, AffectedVersions::fromComposerConstraint($constraint)));
    }

    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function composerRejectedInputProvider(): iterable
    {
        yield 'distribution patched php runtime' => ['8.3.14-1~deb12u1', '>=8.3.0,<8.3.15', true];
        yield 'five part version' => ['13.4.2.3.4', '>=13.0.0,<13.4.11', true];
        yield 'placeholder version' => ['unknown', '>=13.0.0,<13.4.11', false];
        yield 'not applicable version' => ['n/a', '>=13.0.0,<13.4.11', false];
        yield 'branch version' => ['dev-main', '>=13.0.0,<13.4.11', false];
        yield 'unparseable constraint' => ['13.4.2', 'unknown', false];
        yield 'constraint with a trailing comma' => ['13.4.2', '>=13.0.0,<13.4.11,', true];
    }

    #[Test]
    #[DataProvider('hostileInputProvider')]
    public function neverThrowsOnHostileInput(string $version, string $constraint): void
    {
        $this->expectNotToPerformAssertions();

        $this->matcher->satisfies($version, AffectedVersions::fromComposerConstraint($constraint));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function hostileInputProvider(): iterable
    {
        yield 'both sides empty' => ['', ''];
        yield 'version is only separators' => ['...', '>=1.0.0'];
        yield 'version carries a newline' => ["1.0.0\n", '>=1.0.0'];
    }

    #[Test]
    #[DataProvider('comparablePairs')]
    public function canCompareOnlyWhenVersionAndEveryBoundAreNumeric(string $version, string $constraint, bool $expected): void
    {
        self::assertSame($expected, $this->matcher->canCompare($version, AffectedVersions::fromComposerConstraint($constraint)));
    }

    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function comparablePairs(): iterable
    {
        yield 'a range of comparisons' => ['13.4.2', '>=13.0.0, <13.4.11', true];
        yield 'an OR of ranges' => ['8.3.14-1~deb12u1', '>=8.2.0, <8.2.9 || >=8.3.0, <8.3.15', true];
        yield 'a single bar between ranges' => ['13.4.2', '>=13.0.0 | <1.0.0', true];
        yield 'a bare version' => ['13.0.0', '13.0.0', true];
        yield 'v prefixes on both sides' => ['v1.2', '>=v1.0.0', true];
        yield 'a placeholder version' => ['unknown', '>=13.0.0', false];
        yield 'an empty version' => ['', '<2.0.0', false];
        yield 'a branch' => ['dev-main', '<2.0.0', false];
        yield 'a space-separated range' => ['1.5.0', '>=1.0 <2.0', true];
        yield 'a trailing comma' => ['13.4.2', '>=13.0.0, <13.4.11,', true];
        yield 'a word for a constraint' => ['13.4.2', 'unknown', false];
        yield 'no constraint at all' => ['13.4.2', '', false];
    }
}
