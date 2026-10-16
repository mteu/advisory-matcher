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

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Advisory\AdvisoryMatcher;
use mteu\AdvisoryMatcher\Advisory\AdvisoryMatches;
use mteu\AdvisoryMatcher\Advisory\MatchResult;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Version\AffectedVersions;
use mteu\AdvisoryMatcher\Version\LenientVersionMatcher;
use mteu\AdvisoryMatcher\Version\VersionConstraintMatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(AdvisoryMatcher::class)]
#[CoversClass(AdvisoryMatches::class)]
final class AdvisoryMatcherTest extends TestCase
{
    private AdvisoryMatcher $matcher;

    protected function setUp(): void
    {
        $this->matcher = new AdvisoryMatcher(new VersionConstraintMatcher(), new LenientVersionMatcher());
    }

    #[Test]
    public function fallsBackToTheLenientMatcherWhenBuiltWithDefaults(): void
    {
        $matcher = new AdvisoryMatcher();
        $advisory = AdvisoryBuilder::build(affectedVersions: '>=8.3.0, <8.3.15');

        self::assertSame(MatchResult::Affected, $matcher->match($advisory, '8.3.14'));
        self::assertSame(MatchResult::NotAffected, $matcher->match($advisory, '8.3.15'));
        self::assertSame(
            MatchResult::Affected,
            $matcher->match($advisory, '8.3.14-1~deb12u1'),
            'Composer rejects this version, so only the lenient matcher can answer.',
        );
    }

    #[Test]
    #[DataProvider('advisoryRangeProvider')]
    public function reportsWhetherAnAdvisoryCoversTheInstalledVersion(
        string $version,
        string $affectedVersions,
        MatchResult $expected,
    ): void {
        self::assertSame($expected, $this->matcher->match($this->advisory($affectedVersions), $version));
    }

    /**
     * @return iterable<string, array{string, string, MatchResult}>
     */
    public static function advisoryRangeProvider(): iterable
    {
        yield 'version inside the affected range' => ['13.4.2', '>=13.0.0, <13.4.11', MatchResult::Affected];
        yield 'the fixed version itself is not affected' => ['13.4.11', '>=13.0.0, <13.4.11', MatchResult::NotAffected];
        yield 'the introduced version itself is affected' => ['13.0.0', '>=13.0.0, <13.4.11', MatchResult::Affected];
        yield 'version below the affected range' => ['12.4.8', '>=13.0.0, <13.4.11', MatchResult::NotAffected];
        yield 'range without a fixed event stays open ended' => ['13.4.2', '>=13.0.0', MatchResult::Affected];
        yield 'version below an open ended range' => ['12.0.0', '>=13.0.0', MatchResult::NotAffected];

        yield 'first branch of an OR group matches' => ['11.5.30', '>=11.0.0, <11.5.41 || >=12.0.0, <12.4.8', MatchResult::Affected];
        yield 'second branch of an OR group matches' => ['12.4.7', '>=11.0.0, <11.5.41 || >=12.0.0, <12.4.8', MatchResult::Affected];
        yield 'no branch of an OR group matches' => ['12.4.8', '>=11.0.0, <11.5.41 || >=12.0.0, <12.4.8', MatchResult::NotAffected];

        yield 'bare version is an exact match' => ['13.0.0', '13.0.0', MatchResult::Affected];
        yield 'double equals is an exact match' => ['13.0.0', '==13.0.0', MatchResult::Affected];
        yield 'single equals is an exact match' => ['13.0.0', '=13.0.0', MatchResult::Affected];
        yield 'exact match rejects a different patch level' => ['13.0.1', '13.0.0', MatchResult::NotAffected];

        yield 'four part version matches a three part range' => ['13.0.0.0', '>=13.0.0, <13.4.11', MatchResult::Affected];
        yield 'four part version matches a three part equality' => ['13.0.0.0', '13.0.0', MatchResult::Affected];
        yield 'two part version is padded' => ['13.4', '>=13.0.0, <13.4.11', MatchResult::Affected];
        yield 'single part version is padded' => ['13', '>=13.0.0, <13.4.11', MatchResult::Affected];

        yield 'v prefix on the installed version' => ['v13.4.2', '>=13.0.0, <13.4.11', MatchResult::Affected];
        yield 'v prefix inside the constraint' => ['13.4.2', '>=v13.0.0, <v13.4.11', MatchResult::Affected];
        yield 'v prefixed two part version is padded' => ['v1.2', '>=1.0.0, <2.0.0', MatchResult::Affected];

        yield 'padded separators are tolerated' => ['13.4.2', ' >=13.0.0 , <13.4.11 ', MatchResult::Affected];
        yield 'missing space after the comma is tolerated' => ['13.4.2', '>=13.0.0,<13.4.11', MatchResult::Affected];

        yield 'php runtime inside the affected range' => ['8.3.14', '>=8.3.0, <8.3.15', MatchResult::Affected];
        yield 'php runtime outside the affected range' => ['8.4.19', '>=8.3.0, <8.3.15', MatchResult::NotAffected];

        yield 'an empty constraint is undetermined' => ['13.4.2', '', MatchResult::Undetermined];
        yield 'a blank constraint is undetermined' => ['13.4.2', '   ', MatchResult::Undetermined];
    }

    #[Test]
    #[DataProvider('preReleaseProvider')]
    public function keepsPreReleaseVersionsInsideTheirRange(string $version, string $affectedVersions): void
    {
        self::assertSame(MatchResult::Affected, $this->matcher->match($this->advisory($affectedVersions), $version));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function preReleaseProvider(): iterable
    {
        yield 'rc at its own stable lower bound' => ['13.4.0-rc1', '>=13.4.0'];
        yield 'beta at its own stable lower bound' => ['1.0.0-beta3', '>=1.0.0, <2.0.0'];
        yield 'branch alias inside the range' => ['1.0.x-dev', '>=1.0.0, <2.0.0'];
    }

    #[Test]
    public function inheritsComposersAsymmetricPreReleaseOrdering(): void
    {
        self::assertSame(MatchResult::Affected, $this->matcher->match($this->advisory('>=1.0.0'), '1.0.0-beta1'));
        self::assertSame(MatchResult::NotAffected, $this->matcher->match($this->advisory('<1.0.0'), '1.0.0-beta1'));
    }

    #[Test]
    #[DataProvider('unparseableInputProvider')]
    public function answersVersionsComposerCannotParseOrMarksThemUndetermined(
        string $version,
        string $affectedVersions,
        MatchResult $expected,
    ): void {
        self::assertSame($expected, $this->matcher->match($this->advisory($affectedVersions), $version));
    }

    /**
     * @return iterable<string, array{string, string, MatchResult}>
     */
    public static function unparseableInputProvider(): iterable
    {
        yield 'five part version' => ['13.4.2.3.4', '>=13.0.0, <13.4.11', MatchResult::Affected];
        yield 'distribution patched php runtime' => ['8.3.14-1~deb12u1', '>=8.3.0, <8.3.15', MatchResult::Affected];
        yield 'placeholder version' => ['unknown', '>=13.0.0, <13.4.11', MatchResult::Undetermined];
        yield 'placeholder version against an upper bound' => ['unknown', '<2.0.0', MatchResult::Undetermined];
        yield 'empty version' => ['', '>=13.0.0, <13.4.11', MatchResult::Undetermined];
        yield 'empty version against an upper bound' => ['', '<2.0.0', MatchResult::Undetermined];
        yield 'not applicable version' => ['n/a', '>=13.0.0, <13.4.11', MatchResult::Undetermined];
        yield 'branch version' => ['dev-main', '>=13.0.0, <13.4.11', MatchResult::Undetermined];
        yield 'branch name as version' => ['master', '>=13.0.0', MatchResult::Undetermined];
        yield 'unparseable constraint' => ['13.4.2', 'unknown', MatchResult::Undetermined];
        yield 'a trailing comma is tolerated' => ['13.4.2', '>=13.0.0, <13.4.11,', MatchResult::Affected];
    }

    #[Test]
    public function strictMatcherRejectsTheDistributionVersionTheFallbackHandles(): void
    {
        $this->expectException(\UnexpectedValueException::class);

        (new VersionConstraintMatcher())->satisfies('8.3.14-1~deb12u1', '>=8.3.0, <8.3.15');
    }

    #[Test]
    public function sortsEachAdvisoryByHowItMatchesTheVersion(): void
    {
        $covering = $this->advisory('>=13.0.0, <13.4.11', 'GHSA-covering');
        $missing = $this->advisory('>=12.0.0, <12.4.8', 'GHSA-missing');
        $unranged = $this->advisory('', 'GHSA-unranged');

        $matches = $this->matcher->matchAll([$covering, $missing, $unranged], '13.4.2');

        self::assertSame([$covering], $matches->affected);
        self::assertSame([$missing], $matches->notAffected);
        self::assertSame([$unranged], $matches->undetermined);
        self::assertTrue($matches->hasAffected());
        self::assertTrue($matches->hasUndetermined());
    }

    #[Test]
    public function anEmptyAdvisorySetMatchesNothing(): void
    {
        $matches = $this->matcher->matchAll([], '13.4.2');

        self::assertFalse($matches->hasAffected());
        self::assertFalse($matches->hasUndetermined());
        self::assertSame([], $matches->notAffected);
    }

    #[Test]
    public function aVersionNobodyCanPlaceLeavesEveryAdvisoryUndetermined(): void
    {
        $advisories = [$this->advisory('>=12.0.0, <12.4.8', 'GHSA-a'), $this->advisory('<2.0.0', 'GHSA-b')];

        $matches = $this->matcher->matchAll($advisories, 'unknown');

        self::assertSame($advisories, $matches->undetermined);
        self::assertFalse($matches->hasAffected());
    }

    #[Test]
    #[DataProvider('foreignVersionProvider')]
    public function aVersionComposerCannotReadFromAnotherEcosystemIsUndetermined(
        Ecosystem $ecosystem,
        string $version,
    ): void {
        $advisory = AdvisoryBuilder::build(ecosystem: $ecosystem, affectedVersions: '>=1.0.0, <3.0.0');

        self::assertSame(MatchResult::Undetermined, $this->matcher->match($advisory, $version));
    }

    /**
     * @return iterable<string, array{Ecosystem, string}>
     */
    public static function foreignVersionProvider(): iterable
    {
        yield 'npm dotted pre-release' => [Ecosystem::Npm, '1.0.0-alpha.beta.1'];
        yield 'npm next channel' => [Ecosystem::Npm, '2.0.0-next.3'];
        yield 'npm canary build' => [Ecosystem::Npm, '1.0.0-canary.4'];
        yield 'npm numeric pre-release' => [Ecosystem::Npm, '1.0.0-0.3.7'];
    }

    #[Test]
    public function aVersionComposerCanReadFromAnotherEcosystemIsStillAnswered(): void
    {
        $advisory = AdvisoryBuilder::build(ecosystem: Ecosystem::Npm, affectedVersions: '>=1.0.0, <3.0.0');

        self::assertSame(MatchResult::Affected, $this->matcher->match($advisory, '2.1.0'));
        self::assertSame(MatchResult::NotAffected, $this->matcher->match($advisory, '3.0.0'));
    }

    #[Test]
    public function aDistributionPatchedPhpRuntimeIsStillAnsweredByTheFallback(): void
    {
        $advisory = AdvisoryBuilder::build(ecosystem: Ecosystem::Php, affectedVersions: '>=8.3.0, <8.3.15');

        self::assertSame(MatchResult::Affected, $this->matcher->match($advisory, '8.3.14-1~deb12u1'));
    }

    #[Test]
    #[DataProvider('fixedVersionProvider')]
    public function namesTheFixOnTheBranchTheInstallIsOn(
        string $affectedVersions,
        string $installed,
        string $expected,
    ): void {
        self::assertSame($expected, $this->matcher->fixedVersionFor($this->advisory($affectedVersions), $installed));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function fixedVersionProvider(): iterable
    {
        $packagist = '>=1.0,<1.0.5|>=1.1,<1.1.2';
        yield 'Packagist: on the first branch' => [$packagist, '1.0.2', '1.0.5'];
        yield 'Packagist: on the second branch' => [$packagist, '1.1.0', '1.1.2'];
        yield 'Packagist: above every fix' => [$packagist, '1.2.0', ''];
        yield 'Packagist: below every range' => [$packagist, '0.9.0', ''];

        $osv = '>=1.0.0, <1.6.0 || >=2.0.0, <2.1.0';
        yield 'OSV: on the first branch' => [$osv, '1.2.0', '1.6.0'];
        yield 'OSV: on the second branch' => [$osv, '2.0.5', '2.1.0'];
        yield 'OSV: between the branches' => [$osv, '1.8.0', ''];

        yield 'an unbounded range has no fix' => ['>=13.0.0', '13.4.2', ''];
        yield 'a last-affected bound names no fix' => ['>=0, <=1.4.2', '1.0.0', ''];
        yield 'a fix with no lower bound' => ['<1.6.0', '1.0.0', '1.6.0'];
        yield 'space-separated bounds' => ['>=1.0 <1.5', '1.2.0', '1.5'];
        yield 'a version that cannot be placed' => [$packagist, 'unknown', ''];
        yield 'no range at all' => ['', '1.0.0', ''];
    }

    #[Test]
    public function anAdvisoryStatingNoVersionsIsUndetermined(): void
    {
        $advisory = new Advisory(
            advisoryId: 'GHSA-xxxx',
            package: PackageUrl::fromPackageName('composer', 'vendor/package'),
            title: 'A vulnerability',
            link: '',
            cve: '',
            affectedVersions: new AffectedVersions(),
            reportedAt: new \DateTimeImmutable('2026-01-01T00:00:00+00:00'),
            severity: Severity::High,
            references: [],
        );

        self::assertSame(MatchResult::Undetermined, $this->matcher->match($advisory, '1.0.0'));
        self::assertSame('', $this->matcher->fixedVersionFor($advisory, '1.0.0'));
    }

    private function advisory(string $affectedVersions, string $advisoryId = 'GHSA-xxxx'): Advisory
    {
        return AdvisoryBuilder::build(advisoryId: $advisoryId, affectedVersions: $affectedVersions);
    }
}
