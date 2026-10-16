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

use Composer\Semver\CompilingMatcher;
use Composer\Semver\Semver;
use mteu\AdvisoryMatcher\Version\VersionConstraintMatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(VersionConstraintMatcher::class)]
final class VersionConstraintMatcherTest extends TestCase
{
    private VersionConstraintMatcher $matcher;

    protected function setUp(): void
    {
        $this->matcher = new VersionConstraintMatcher();
    }

    #[Test]
    public function matchingLeavesNoProcessWideState(): void
    {
        CompilingMatcher::clear();

        foreach (['1.0.0', '1.5.0', '2.0.0', '2.1.0'] as $version) {
            $this->matcher->satisfies($version, '>=1.0.0,<2.0.0 || >=2.1.0');
        }

        foreach (['resultCache', 'compiledCheckerCache'] as $staticCache) {
            self::assertSame(
                [],
                (new \ReflectionProperty(CompilingMatcher::class, $staticCache))->getValue(),
                sprintf('CompilingMatcher::$%s was filled.', $staticCache),
            );
        }
    }

    #[Test]
    #[DataProvider('affectedVersionProvider')]
    public function reportsWhetherVersionFallsInsideConstraint(
        string $version,
        string $constraint,
        bool $expected,
    ): void {
        self::assertSame($expected, $this->matcher->satisfies($version, $constraint));
    }

    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function affectedVersionProvider(): iterable
    {
        yield 'exact version inside range' => ['1.2.3', '>=1.0.0,<2.0.0', true];
        yield 'version on lower bound' => ['1.0.0', '>=1.0.0,<2.0.0', true];
        yield 'version on exclusive upper bound' => ['2.0.0', '>=1.0.0,<2.0.0', false];
        yield 'version below range' => ['0.9.0', '>=1.0.0,<2.0.0', false];

        yield 'caret constraint matches same major' => ['1.9.0', '^1.2', true];
        yield 'caret constraint rejects next major' => ['2.0.0', '^1.2', false];
        yield 'tilde constraint matches same minor' => ['1.2.9', '~1.2.0', true];
        yield 'tilde constraint rejects next minor' => ['1.3.0', '~1.2.0', false];
        yield 'wildcard constraint matches patch releases' => ['1.2.7', '1.2.*', true];
        yield 'wildcard constraint rejects other minor' => ['1.3.0', '1.2.*', false];

        yield 'v prefix is tolerated' => ['v1.2.3', '>=1.0.0,<2.0.0', true];
        yield 'trailing zero segment is equivalent' => ['13.0.0.0', '13.0.0', true];

        yield 'or constraint matches first branch' => ['1.5.0', '>=1.0,<1.6 || >=2.0,<2.1', true];
        yield 'or constraint matches second branch' => ['2.0.5', '>=1.0,<1.6 || >=2.0,<2.1', true];
        yield 'or constraint matches neither branch' => ['1.8.0', '>=1.0,<1.6 || >=2.0,<2.1', false];
        yield 'single pipe separator is accepted' => ['1.5.0', '>=1.0,<1.6|>=2.0,<2.1', true];
        yield 'match-all constraint covers any version' => ['1.0.0', '*', true];
    }

    #[Test]
    #[DataProvider('preReleaseVersionProvider')]
    public function followsComposerSemanticsForPreReleaseVersions(
        string $version,
        string $constraint,
        bool $expected,
    ): void {
        self::assertSame($expected, $this->matcher->satisfies($version, $constraint));
    }

    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function preReleaseVersionProvider(): iterable
    {
        yield 'pre-release satisfies a stable lower bound' => ['1.0.0-beta1', '>=1.0.0', true];
        yield 'pre-release fails a stable upper bound' => ['1.0.0-beta1', '<1.0.0', false];
        yield 'pre-release is excluded by the stable upper bound of a range' => [
            '1.0.0-beta1',
            '>=1.0.0-alpha1,<1.0.0',
            false,
        ];
        yield 'pre-release inside an explicit pre-release range' => [
            '1.0.0-beta1',
            '>=1.0.0-alpha1,<1.0.0-rc1',
            true,
        ];
        yield 'pre-release ordering follows the suffix' => ['1.0.0-beta1', '>1.0.0-alpha1', true];
        yield 'advisory range still covers a pre-release below its upper bound' => [
            '1.0.0-beta1',
            '>=1.0.0,<1.6.0',
            true,
        ];
        yield 'pre-release satisfies a stable caret' => ['1.0.0-alpha', '^1.0', true];
    }

    /**
     * The matcher exists only to stop composer/semver re-parsing the same
     * strings, so it must answer exactly what composer/semver answers. The
     * expectation tables above say what the answer is; this says the
     * memoisation did not change it, so an upstream change and a caching
     * defect fail in different places.
     */
    #[Test]
    #[DataProvider('everyCaseProvider')]
    public function answersExactlyWhatComposerSemverAnswers(string $version, string $constraint): void
    {
        self::assertSame(
            Semver::satisfies($version, $constraint),
            $this->matcher->satisfies($version, $constraint),
        );
    }

    /**
     * Every case in this file, reduced to the question alone.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function everyCaseProvider(): iterable
    {
        foreach (self::affectedVersionProvider() as $name => [$version, $constraint]) {
            yield $name => [$version, $constraint];
        }

        foreach (self::preReleaseVersionProvider() as $name => [$version, $constraint]) {
            yield 'pre-release: ' . $name => [$version, $constraint];
        }

        yield from self::composerEdgeCaseProvider();
    }

    /**
     * Corners of Composer's constraint language no advisory feed is known to
     * emit, listed for the equivalence check only: what matters is that the
     * matcher agrees with composer/semver there too, not what the answer is.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function composerEdgeCaseProvider(): iterable
    {
        yield 'dev suffix against a stable lower bound' => ['1.0.0-dev', '>=1.0.0'];
        yield 'branch alias against a caret' => ['1.0.x-dev', '^1.0'];
        yield 'branch name against match-all' => ['dev-main', '*'];
        yield 'not-equal' => ['2.0.0', '!=2.0.0'];
        yield 'hyphen range, inside' => ['1.0.0', '1.0 - 2.0'];
        yield 'hyphen range, outside' => ['2.5.0', '1.0 - 2.0'];
        yield 'patch suffix against a lower bound' => ['1.0.0-p1', '>=1.0.0'];
        yield 'patch suffix against an upper bound' => ['1.0.0-patch1', '<=1.0.0'];
        yield 'caret below 1.0, inside' => ['0.1.0', '^0.1'];
        yield 'caret below 1.0, next minor' => ['0.2.0', '^0.1'];
        yield 'pre-release of the exclusive upper bound' => ['2.0.0-RC1', '>=1.0.0,<2.0.0'];
    }

    #[Test]
    public function aRejectedInputLeavesTheCachesUsable(): void
    {
        // Nothing is cached when parsing throws, so the rejection repeats and
        // the answers around it are unaffected.
        self::assertTrue($this->matcher->satisfies('1.5.0', '^1.0'));

        for ($attempt = 0; $attempt < 2; $attempt++) {
            try {
                $this->matcher->satisfies('unparseable', '^1.0');
                self::fail('Expected an UnexpectedValueException on attempt ' . $attempt . '.');
            } catch (\UnexpectedValueException) {
                // expected
            }
        }

        self::assertTrue($this->matcher->satisfies('1.5.0', '^1.0'));
        self::assertFalse($this->matcher->satisfies('2.0.0', '^1.0'));
    }

    #[Test]
    public function answersConsistentlyWhenQuestionsAreInterleaved(): void
    {
        $questions = [
            ['1.5.0', '^1.0', true],
            ['2.0.0', '^1.0', false],
            ['1.0.5', '1.0.*', true],
            ['13.4.11', '>=13.0.0,<13.4.12', true],
            ['1.0.0-beta1', '>=1.0.0', true],
        ];

        // Interleaved rather than grouped, so a cache that answered from the
        // previous call instead of from its key would disagree with itself.
        for ($round = 0; $round < 3; $round++) {
            foreach ($questions as [$version, $constraint, $expected]) {
                self::assertSame(
                    $expected,
                    $this->matcher->satisfies($version, $constraint),
                    sprintf('%s against %s, round %d', $version, $constraint, $round),
                );
            }
        }
    }

    #[Test]
    public function answersConsistentlyWhenTheSameQuestionIsAskedTwice(): void
    {
        $first = $this->matcher->satisfies('1.2.3', '>=1.0.0,<2.0.0');
        $second = $this->matcher->satisfies('1.2.3', '>=1.0.0,<2.0.0');

        self::assertTrue($first);
        self::assertSame($first, $second);
    }

    #[Test]
    public function distinguishesVersionsThatShareAConstraint(): void
    {
        self::assertTrue($this->matcher->satisfies('1.2.3', '^1.0'));
        self::assertFalse($this->matcher->satisfies('2.2.3', '^1.0'));
    }

    #[Test]
    public function distinguishesConstraintsThatShareAVersion(): void
    {
        self::assertTrue($this->matcher->satisfies('1.2.3', '^1.0'));
        self::assertFalse($this->matcher->satisfies('1.2.3', '^2.0'));
    }

    #[Test]
    public function throwsOnAnUnparseableVersion(): void
    {
        $this->expectException(\UnexpectedValueException::class);

        $this->matcher->satisfies('unknown', '>=1.0.0');
    }

    #[Test]
    public function throwsOnADistributionVersionRatherThanGuessing(): void
    {
        // Installed versions read off a distribution package look like this.
        // The matcher must refuse them, so a caller can fall back deliberately
        // instead of receiving a confident wrong answer.
        $this->expectException(\UnexpectedValueException::class);

        $this->matcher->satisfies('8.3.14-1~deb12u1', '^8.3');
    }

    #[Test]
    public function throwsOnAnUnparseableConstraint(): void
    {
        $this->expectException(\UnexpectedValueException::class);

        $this->matcher->satisfies('1.2.3', 'not a constraint');
    }
}
