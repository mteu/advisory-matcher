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
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Source\AdvisoryBatch;
use mteu\AdvisoryMatcher\Source\AnsweredPackage;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use mteu\AdvisoryMatcher\Tests\Unit\Advisory\AdvisoryBuilder;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(AdvisoryBatch::class)]
final class AdvisoryBatchTest extends TestCase
{
    #[Test]
    public function anEmptyBatchWithNoFailuresIsComplete(): void
    {
        self::assertTrue((new AdvisoryBatch())->isComplete());
    }

    #[Test]
    public function aBatchCarryingAFailureIsNotComplete(): void
    {
        $batch = new AdvisoryBatch(failures: [$this->failure()]);

        self::assertFalse($batch->isComplete());
    }

    #[Test]
    public function anEmptyBatchAnswersForNothing(): void
    {
        self::assertFalse((new AdvisoryBatch())->wasAnsweredFor($this->package('vendor/one')));
    }

    #[Test]
    public function aPackageWithNoAdvisoriesIsStillAnsweredFor(): void
    {
        $asked = $this->package('vendor/one');
        $batch = new AdvisoryBatch(answeredFor: [new AnsweredPackage($asked)]);

        self::assertTrue($batch->wasAnsweredFor($asked));
        self::assertSame([], $batch->advisoriesFor($asked));
        self::assertFalse($batch->wasAnsweredFor($this->package('vendor/never-asked')));
    }

    #[Test]
    public function answersAreMatchedOnTheWholeReferenceIncludingVersion(): void
    {
        $batch = new AdvisoryBatch(answeredFor: [new AnsweredPackage($this->package('vendor/one', '1.0.0'))]);

        self::assertTrue($batch->wasAnsweredFor($this->package('vendor/one', '1.0.0')));
        self::assertFalse($batch->wasAnsweredFor($this->package('vendor/one', '1.0.1')));
        self::assertFalse(
            $batch->wasAnsweredFor(new PackageRef(PackageUrl::fromPackageName('npm', 'vendor/one'), '1.0.0')),
        );
    }

    #[Test]
    public function advisoriesAreFiledUnderTheirPackage(): void
    {
        $one = AdvisoryBuilder::build(advisoryId: 'PKSA-one', packageName: 'vendor/one');
        $two = AdvisoryBuilder::build(advisoryId: 'PKSA-two', packageName: 'vendor/two');

        $batch = new AdvisoryBatch(answeredFor: [
            new AnsweredPackage($this->package('vendor/one'), advisories: [$one]),
            new AnsweredPackage($this->package('vendor/two'), advisories: [$two]),
        ]);

        self::assertSame([$one], $batch->advisoriesFor($this->package('vendor/one')));
        self::assertSame([$two], $batch->advisoriesFor($this->package('vendor/two')));
    }

    #[Test]
    public function advisoriesAreNotFilteredByWhetherTheyAffectTheVersion(): void
    {
        $advisory = AdvisoryBuilder::build(packageName: 'vendor/one', affectedVersions: '>=9.0.0,<9.1.0');

        $batch = $this->batchAnswering($this->package('vendor/one', '1.0.0'), $advisory);

        self::assertSame([$advisory], $batch->advisoriesFor($this->package('vendor/one', '1.0.0')));
    }

    #[Test]
    public function mergeConcatenatesFailures(): void
    {
        $left = new AdvisoryBatch(failures: [$this->failure('Packagist')]);
        $right = new AdvisoryBatch(failures: [$this->failure('OSV')]);

        $merged = $left->merge($right);

        self::assertCount(2, $merged->failures);
        self::assertFalse($merged->isComplete());
    }

    #[Test]
    public function aPackageAnsweredByOneSourceAndFailedByAnotherIsAnsweredFor(): void
    {
        $package = $this->package('vendor/one');

        $answered = new AdvisoryBatch(answeredFor: [new AnsweredPackage($package)]);
        $failed = new AdvisoryBatch(failures: [$this->failure()]);

        $merged = $answered->merge($failed);

        self::assertTrue($merged->wasAnsweredFor($package));
        self::assertFalse($merged->isComplete());
    }

    #[Test]
    public function mergeUnionsAnsweredPackagesWithoutDuplicating(): void
    {
        $shared = $this->package('vendor/one');
        $onlyRight = $this->package('vendor/two');

        $merged = (new AdvisoryBatch(answeredFor: [new AnsweredPackage($shared)]))
            ->merge(new AdvisoryBatch(answeredFor: [new AnsweredPackage($shared), new AnsweredPackage($onlyRight)]));

        self::assertCount(2, $merged->answeredFor);
        self::assertTrue($merged->wasAnsweredFor($shared));
        self::assertTrue($merged->wasAnsweredFor($onlyRight));
    }

    #[Test]
    public function advisoriesAreFiledUnderTheEcosystemAsWellAsTheName(): void
    {
        $npm = new PackageRef(PackageUrl::fromPackageName('npm', 'debug'), '2.6.8');
        $composer = new PackageRef(PackageUrl::fromPackageName('composer', 'debug'), '0.3');
        $npmAdvisory = AdvisoryBuilder::build(packageName: 'debug', ecosystem: Ecosystem::Npm, cve: 'CVE-2017-16137');
        $batch = new AdvisoryBatch(answeredFor: [
            new AnsweredPackage($npm, advisories: [$npmAdvisory]),
            new AnsweredPackage($composer),
        ]);

        self::assertSame([$npmAdvisory], $batch->advisoriesFor($npm));
        self::assertSame([], $batch->advisoriesFor($composer));
    }

    #[Test]
    public function aPackageNobodyAnsweredIsUnansweredEvenInACompleteBatch(): void
    {
        $answered = $this->package('vendor/known');
        $unknown = $this->package('vendor/typo');
        $batch = new AdvisoryBatch(answeredFor: [new AnsweredPackage($answered)]);

        self::assertTrue($batch->isComplete());
        self::assertSame([$unknown], $batch->unansweredAmong([$answered, $unknown]));
    }

    #[Test]
    public function unansweredPackagesKeepTheOrderTheyWereAskedIn(): void
    {
        $first = $this->package('vendor/first');
        $answered = $this->package('vendor/answered');
        $second = $this->package('vendor/second');
        $batch = new AdvisoryBatch(answeredFor: [new AnsweredPackage($answered)]);

        self::assertSame([$first, $second], $batch->unansweredAmong([$first, $answered, $second]));
    }

    #[Test]
    public function anAnswerForAnotherVersionLeavesThisVersionUnanswered(): void
    {
        $asked = $this->package('vendor/example', '2.0.0');
        $batch = new AdvisoryBatch(answeredFor: [new AnsweredPackage($this->package('vendor/example', '1.0.0'))]);

        self::assertSame([$asked], $batch->unansweredAmong([$asked]));
    }

    #[Test]
    public function nothingIsUnansweredWhenNothingWasAsked(): void
    {
        self::assertSame([], (new AdvisoryBatch())->unansweredAmong([]));
    }

    #[Test]
    public function mergingAnEmptyBatchChangesNothing(): void
    {
        $advisory = AdvisoryBuilder::build(packageName: 'vendor/one');
        $package = $this->package('vendor/one');

        $batch = $this->batchAnswering($package, $advisory);

        $merged = $batch->merge(new AdvisoryBatch());

        self::assertSame([$advisory], $merged->advisories);
        self::assertTrue($merged->wasAnsweredFor($package));
        self::assertTrue($merged->isComplete());
    }

    #[Test]
    public function twoVersionsOfOnePackageKeepTheirOwnAdvisories(): void
    {
        $newer = new PackageRef(PackageUrl::fromPackageName('generic', 'php'), '8.3.14');
        $older = new PackageRef(PackageUrl::fromPackageName('generic', 'php'), '8.2.10');
        $forNewer = AdvisoryBuilder::build(
            advisoryId: 'NVD-CVE-2026-0001',
            packageName: 'php',
            ecosystem: Ecosystem::Php,
            cve: 'CVE-2026-0001',
            firstPatchedVersion: '8.3.15',
        );
        $forOlder = AdvisoryBuilder::build(
            advisoryId: 'NVD-CVE-2026-0001',
            packageName: 'php',
            ecosystem: Ecosystem::Php,
            cve: 'CVE-2026-0001',
            firstPatchedVersion: '8.2.27',
        );
        $onlyOlder = AdvisoryBuilder::build(
            advisoryId: 'NVD-CVE-2026-0002',
            packageName: 'php',
            ecosystem: Ecosystem::Php,
            cve: 'CVE-2026-0002',
        );

        $batch = $this->batchAnswering($newer, $forNewer)->merge($this->batchAnswering($older, $forOlder, $onlyOlder));

        self::assertSame([$forNewer], $batch->advisoriesFor($newer));
        self::assertSame([$forOlder, $onlyOlder], $batch->advisoriesFor($older));
        self::assertSame('8.3.15', $batch->advisoriesFor($newer)[0]->firstPatchedVersion);
        self::assertCount(3, $batch->advisories);
    }

    #[Test]
    public function onePackageAnsweredByTwoFeedsIsOneAnswerHoldingBothReports(): void
    {
        $package = $this->package('vendor/one');
        $first = AdvisoryBuilder::build(advisoryId: 'PKSA-zzzz', packageName: 'vendor/one', cve: 'CVE-2026-0001');
        $second = AdvisoryBuilder::build(advisoryId: 'OSV-GHSA-x', packageName: 'vendor/one', cve: 'CVE-2026-0001');

        $batch = new AdvisoryBatch(answeredFor: [
            new AnsweredPackage($package, advisories: [$first]),
            new AnsweredPackage($package, advisories: [$second]),
        ]);

        self::assertCount(1, $batch->answeredFor);
        self::assertSame([$first, $second], $batch->advisoriesFor($package));
    }

    #[Test]
    public function theSameRecordDeliveredTwiceForOnePackageIsKeptOnce(): void
    {
        $package = $this->package('vendor/one');
        $advisory = AdvisoryBuilder::build(packageName: 'vendor/one');

        $batch = new AdvisoryBatch(answeredFor: [
            new AnsweredPackage($package, advisories: [$advisory]),
            new AnsweredPackage($package, advisories: [$advisory]),
        ]);

        self::assertSame([$advisory], $batch->advisoriesFor($package));
    }

    private function batchAnswering(PackageRef $package, Advisory ...$advisories): AdvisoryBatch
    {
        return new AdvisoryBatch(answeredFor: [new AnsweredPackage($package, advisories: array_values($advisories))]);
    }

    private function package(string $name, string $version = '1.0.0'): PackageRef
    {
        return new PackageRef(PackageUrl::fromPackageName('composer', $name), $version);
    }

    private function failure(string $sourceName = 'Packagist'): SourceFailure
    {
        return new SourceFailure(
            sourceName: $sourceName,
            ecosystem: Ecosystem::Composer,
            reason: FailureReason::Timeout,
            detail: 'timed out after 10s',
        );
    }
}
