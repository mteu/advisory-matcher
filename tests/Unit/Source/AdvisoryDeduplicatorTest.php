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

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\AdvisoryReference;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\AdvisoryBatch;
use mteu\AdvisoryMatcher\Source\AdvisoryDeduplicator;
use mteu\AdvisoryMatcher\Source\AnsweredPackage;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use mteu\AdvisoryMatcher\Tests\Unit\Advisory\AdvisoryBuilder;
use mteu\AdvisoryMatcher\Version\AffectedVersions;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(AdvisoryDeduplicator::class)]
final class AdvisoryDeduplicatorTest extends TestCase
{
    private AdvisoryDeduplicator $deduplicator;

    protected function setUp(): void
    {
        $this->deduplicator = new AdvisoryDeduplicator();
    }

    #[Test]
    public function foldsOnlyWithinOnePackageAndKeepsFailures(): void
    {
        $failure = new SourceFailure('OSV', Ecosystem::Npm, FailureReason::Timeout, 'timed out');
        $first = AdvisoryBuilder::build(advisoryId: 'PKSA-1', packageName: 'vendor/one', cve: 'CVE-2026-0001');
        $second = AdvisoryBuilder::build(advisoryId: 'OSV-GHSA-x', packageName: 'vendor/one', cve: 'CVE-2026-0001');
        $package = $this->package('vendor/one');

        $batch = $this->deduplicator->deduplicate(new AdvisoryBatch(
            answeredFor: [new AnsweredPackage($package, [$first, $second])],
            failures: [$failure],
        ));

        self::assertCount(1, $batch->advisoriesFor($package));
        self::assertSame([$failure], $batch->failures);
    }

    #[Test]
    public function leavesDistinctVulnerabilitiesApart(): void
    {
        $package = $this->package('vendor/one');
        $first = AdvisoryBuilder::build(advisoryId: 'PKSA-1', packageName: 'vendor/one', cve: 'CVE-2026-0001');
        $second = AdvisoryBuilder::build(advisoryId: 'PKSA-2', packageName: 'vendor/one', cve: 'CVE-2026-0002');

        $batch = $this->deduplicator->deduplicate($this->batchAnswering($package, $first, $second));

        self::assertSame([$first, $second], $batch->advisoriesFor($package));
    }

    #[Test]
    public function keepsDescriptiveFieldsOfTheRecordAlreadyHeld(): void
    {
        $held = AdvisoryBuilder::build(
            advisoryId: 'PKSA-held',
            title: 'Held title',
            link: 'https://held.invalid',
            cve: 'CVE-2026-0001',
        );
        $other = AdvisoryBuilder::build(
            advisoryId: 'OSV-other',
            title: 'Other title',
            link: 'https://other.invalid',
            cve: 'CVE-2026-0001',
        );

        $merged = $this->merged($held, $other);

        self::assertSame('PKSA-held', $merged->advisoryId);
        self::assertSame('Held title', $merged->title);
        self::assertSame('https://held.invalid', $merged->link);
    }

    #[Test]
    public function takesTheMoreAlarmingSeverityWhicheverSideCarriesIt(): void
    {
        $medium = AdvisoryBuilder::build(severity: Severity::Medium);
        $critical = AdvisoryBuilder::build(severity: Severity::Critical);

        self::assertSame(Severity::Critical, $this->merged($medium, $critical)->severity);
        self::assertSame(Severity::Critical, $this->merged($critical, $medium)->severity);
    }

    /**
     * @return iterable<string, array{Severity, Severity, Severity}>
     */
    public static function unknownSeverityMerges(): iterable
    {
        yield 'unknown outranks medium' => [Severity::Unknown, Severity::Medium, Severity::Unknown];
        yield 'medium does not replace unknown' => [Severity::Medium, Severity::Unknown, Severity::Unknown];
        yield 'critical outranks unknown' => [Severity::Unknown, Severity::Critical, Severity::Critical];
        yield 'a known high replaces an unknown' => [Severity::Unknown, Severity::High, Severity::High];
        yield 'a known high is not replaced by an unknown' => [Severity::High, Severity::Unknown, Severity::High];
    }

    #[Test]
    #[DataProvider('unknownSeverityMerges')]
    public function anUnknownSeverityNeverMakesAMergedFindingLookSafer(
        Severity $held,
        Severity $other,
        Severity $expected,
    ): void {
        $merged = $this->merged(AdvisoryBuilder::build(severity: $held), AdvisoryBuilder::build(severity: $other));

        self::assertSame($expected, $merged->severity);
    }

    #[Test]
    public function fillsAMissingCveFromTheOtherRecord(): void
    {
        $withoutCve = AdvisoryBuilder::build(cve: '');
        $withCve = AdvisoryBuilder::build(cve: 'CVE-2026-1234');

        self::assertSame('CVE-2026-1234', $this->merged($withoutCve, $withCve)->cve);
    }

    #[Test]
    public function keepsItsOwnCveRatherThanTheOthers(): void
    {
        $held = AdvisoryBuilder::build(cve: 'CVE-2026-1111');
        $other = AdvisoryBuilder::build(cve: 'CVE-2026-2222');

        self::assertSame('CVE-2026-1111', $this->merged($held, $other)->cve);
    }

    #[Test]
    public function unionsRangesTheFeedsDisagreeOn(): void
    {
        $held = AdvisoryBuilder::build(affectedVersions: '>=1.0.0,<1.6.0');
        $other = AdvisoryBuilder::build(affectedVersions: '>=2.0.0,<2.1.0');

        self::assertSame(
            '>=1.0.0,<1.6.0 || >=2.0.0,<2.1.0',
            $this->merged($held, $other)->affectedVersions->toComposerConstraint(),
        );
    }

    #[Test]
    #[DataProvider('equivalentConstraintProvider')]
    public function keepsOneCopyOfARangeBothFeedsState(string $left, string $right): void
    {
        $merged = $this->merged(
            AdvisoryBuilder::build(affectedVersions: $left),
            AdvisoryBuilder::build(affectedVersions: $right),
        );

        self::assertSame(
            AffectedVersions::fromComposerConstraint($left)->toComposerConstraint(),
            $merged->affectedVersions->toComposerConstraint(),
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function equivalentConstraintProvider(): iterable
    {
        yield 'identical' => ['>=1.0.0,<1.6.0', '>=1.0.0,<1.6.0'];
        yield 'differing whitespace' => ['>=1.0.0,<1.6.0', '>=1.0.0, <1.6.0'];
        yield 'differing or separator' => ['>=1.0.0|<0.9.0', '>=1.0.0||<0.9.0'];
    }

    #[Test]
    #[DataProvider("emptyConstraintProvider")]
    public function ignoresAFeedThatStatesNoRanges(
        string $left,
        string $right,
        string $expected,
    ): void {
        $merged = $this->merged(
            AdvisoryBuilder::build(affectedVersions: $left),
            AdvisoryBuilder::build(affectedVersions: $right),
        );

        self::assertSame($expected, $merged->affectedVersions->toComposerConstraint());
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function emptyConstraintProvider(): iterable
    {
        yield 'other side empty' => ['>=1.0.0,<1.6.0', '', '>=1.0.0,<1.6.0'];
        yield 'held side empty' => ['', '>=2.0.0,<2.1.0', '>=2.0.0,<2.1.0'];
        yield 'both empty' => ['', '', ''];
    }

    #[Test]
    #[DataProvider('patchedVersionProvider')]
    public function takesTheNearestPatchedVersion(string $left, string $right, string $expected): void
    {
        $merged = $this->merged(
            AdvisoryBuilder::build(firstPatchedVersion: $left),
            AdvisoryBuilder::build(firstPatchedVersion: $right),
        );

        self::assertSame($expected, $merged->firstPatchedVersion);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function patchedVersionProvider(): iterable
    {
        yield 'lower on the held side' => ['1.6.0', '2.0.0', '1.6.0'];
        yield 'lower on the other side' => ['2.0.0', '1.6.0', '1.6.0'];
        yield 'only the other side names one' => ['', '1.6.0', '1.6.0'];
        yield 'only the held side names one' => ['1.6.0', '', '1.6.0'];
        yield 'neither names one' => ['', '', ''];
    }

    #[Test]
    public function collectsReferencesFromBothSidesWithoutDuplicates(): void
    {
        $held = AdvisoryBuilder::build(references: [
            new AdvisoryReference('packagist', 'PKSA-1111'),
            new AdvisoryReference('github', 'GHSA-aaaa-bbbb-cccc'),
        ]);
        $other = AdvisoryBuilder::build(references: [
            new AdvisoryReference('github', 'GHSA-aaaa-bbbb-cccc'),
            new AdvisoryReference('osv', 'OSV-GHSA-aaaa-bbbb-cccc'),
        ]);

        $merged = $this->merged($held, $other);

        self::assertCount(3, $merged->references);
        self::assertSame(
            ['packagist|PKSA-1111', 'github|GHSA-aaaa-bbbb-cccc', 'osv|OSV-GHSA-aaaa-bbbb-cccc'],
            array_map(
                static fn (AdvisoryReference $reference): string => $reference->name . '|' . $reference->remoteId,
                $merged->references,
            ),
        );
    }

    #[Test]
    public function foldsTwoFeedsReportsOfOneVulnerability(): void
    {
        $osv = AdvisoryBuilder::build(
            advisoryId: 'OSV-GHSA-aaaa-bbbb-cccc',
            packageName: 'vendor/one',
            cve: 'CVE-2026-0001',
        );
        $packagist = AdvisoryBuilder::build(
            advisoryId: 'PKSA-zzzz',
            packageName: 'vendor/one',
            cve: 'CVE-2026-0001',
        );

        $merged = $this->deduplicator->deduplicate($this->batchAnswering($this->package('vendor/one'), $osv)
            ->merge($this->batchAnswering($this->package('vendor/one'), $packagist)));

        self::assertCount(1, $merged->advisories);
    }

    #[Test]
    public function keepsOneVulnerabilityAffectingTwoPackagesApart(): void
    {
        $one = AdvisoryBuilder::build(packageName: 'vendor/one', cve: 'CVE-2026-0001');
        $two = AdvisoryBuilder::build(packageName: 'vendor/two', cve: 'CVE-2026-0001');

        $merged = $this->deduplicator->deduplicate($this->batchAnswering($this->package('vendor/one'), $one)
            ->merge($this->batchAnswering($this->package('vendor/two'), $two)));

        self::assertCount(2, $merged->advisories);
    }

    #[Test]
    public function foldsRecordsThatShareOnlyTheirGithubAdvisoryId(): void
    {
        $withCve = AdvisoryBuilder::build(
            advisoryId: 'PKSA-zzzz',
            packageName: 'vendor/one',
            remoteId: 'GHSA-aaaa-bbbb-cccc',
            cve: 'CVE-2026-0001',
        );
        $withoutCve = AdvisoryBuilder::build(
            advisoryId: 'OSV-GHSA-aaaa-bbbb-cccc',
            packageName: 'vendor/one',
            cve: '',
        );

        $merged = $this->deduplicator->deduplicate($this->batchAnswering($this->package('vendor/one'), $withCve)
            ->merge($this->batchAnswering($this->package('vendor/one'), $withoutCve)));

        self::assertCount(1, $merged->advisories);
    }

    #[Test]
    public function foldingADuplicateNeverMakesAPackageLookSafer(): void
    {
        $milder = AdvisoryBuilder::build(
            advisoryId: 'PKSA-zzzz',
            packageName: 'vendor/one',
            cve: 'CVE-2026-0001',
            affectedVersions: '>=1.0.0,<1.2.0',
            severity: Severity::Medium,
        );
        $harsher = AdvisoryBuilder::build(
            advisoryId: 'OSV-GHSA-aaaa-bbbb-cccc',
            packageName: 'vendor/one',
            cve: 'CVE-2026-0001',
            affectedVersions: '>=1.4.0,<1.6.0',
            severity: Severity::Critical,
        );

        $merged = $this->deduplicator->deduplicate($this->batchAnswering($this->package('vendor/one'), $milder)
            ->merge($this->batchAnswering($this->package('vendor/one'), $harsher)));

        self::assertCount(1, $merged->advisories);
        self::assertSame(Severity::Critical, $merged->advisories[0]->severity);
        self::assertStringContainsString('>=1.0.0,<1.2.0', $merged->advisories[0]->affectedVersions->toComposerConstraint());
        self::assertStringContainsString('>=1.4.0,<1.6.0', $merged->advisories[0]->affectedVersions->toComposerConstraint());
    }

    #[Test]
    public function aThirdReportFindsAnEntryMatchedByADifferentIdentity(): void
    {
        $byGhsa = AdvisoryBuilder::build(
            advisoryId: 'OSV-GHSA-aaaa-bbbb-cccc',
            packageName: 'vendor/one',
            cve: '',
        );
        $bridging = AdvisoryBuilder::build(
            advisoryId: 'PKSA-zzzz',
            packageName: 'vendor/one',
            remoteId: 'GHSA-aaaa-bbbb-cccc',
            cve: 'CVE-2026-0001',
        );
        $byCve = AdvisoryBuilder::build(
            advisoryId: 'NVD-CVE-2026-0001',
            packageName: 'vendor/one',
            cve: 'CVE-2026-0001',
        );

        $package = $this->package('vendor/one');
        $merged = $this->deduplicator->deduplicate($this->batchAnswering($package, $byGhsa)
            ->merge($this->batchAnswering($package, $bridging))
            ->merge($this->batchAnswering($package, $byCve)));

        self::assertCount(1, $merged->advisories);
    }

    #[Test]
    public function keepsOneCveInTwoEcosystemsApart(): void
    {
        $npm = AdvisoryBuilder::build(
            packageName: 'x',
            ecosystem: Ecosystem::Npm,
            cve: 'CVE-2026-1234',
            affectedVersions: '>=1.0,<1.2',
        );
        $composer = AdvisoryBuilder::build(
            packageName: 'x',
            ecosystem: Ecosystem::Composer,
            cve: 'CVE-2026-1234',
            affectedVersions: '>=5.0,<5.1',
        );

        $merged = $this->deduplicator->deduplicate($this->batchAnswering(new PackageRef(Ecosystem::Npm, 'x', '1.1'), $npm)
            ->merge($this->batchAnswering(new PackageRef(Ecosystem::Composer, 'x', '5.0'), $composer)));

        self::assertSame([$npm, $composer], $merged->advisories);
    }

    private function merged(Advisory $held, Advisory $other): Advisory
    {
        $package = $this->package($held->packageName);
        $folded = $this->deduplicator->deduplicate($this->batchAnswering($package, $held, $other))->advisoriesFor($package);

        self::assertCount(1, $folded, 'The two records were not recognised as one vulnerability.');

        return $folded[0];
    }

    private function batchAnswering(PackageRef $package, Advisory ...$advisories): AdvisoryBatch
    {
        return new AdvisoryBatch(answeredFor: [new AnsweredPackage($package, array_values($advisories))]);
    }

    private function package(string $name): PackageRef
    {
        return new PackageRef(Ecosystem::Composer, $name, '1.0.0');
    }
}
