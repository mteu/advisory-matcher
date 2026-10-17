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
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Source\AdvisoryBatch;
use mteu\AdvisoryMatcher\Source\AdvisorySource;
use mteu\AdvisoryMatcher\Source\AnsweredPackage;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Source\SeverityEnrichingAdvisorySource;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use mteu\AdvisoryMatcher\Tests\Unit\Advisory\AdvisoryBuilder;
use mteu\AdvisoryMatcher\Tests\Unit\Source\Http\CollectingLogger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(SeverityEnrichingAdvisorySource::class)]
final class SeverityEnrichingAdvisorySourceTest extends TestCase
{
    private const string CVE = 'CVE-2026-109162';

    #[Test]
    public function anUnknownAdvisoryWithACveIsRatedFromItsCveRecord(): void
    {
        $form = $this->package('typo3/cms-form');
        $lookup = new SeverityLookupStub([self::CVE => Severity::Critical]);
        $logger = new CollectingLogger();

        $batch = $this->subject(
            $this->answering(['typo3/cms-form' => [$this->unknown('TYPO3-CORE-SA-2026-024', self::CVE)]]),
            $lookup,
            logger: $logger,
        )->advisoriesFor([$form]);

        self::assertTrue($batch->wasAnsweredFor($form));
        self::assertSame(['TYPO3-CORE-SA-2026-024' => Severity::Critical], $this->severitiesIn($batch->advisoriesFor($form)));
        self::assertSame([self::CVE], $lookup->lookedUp());
        self::assertSame([[self::CVE]], $lookup->storedAskedFor());
        self::assertSame([], $logger->records());
    }

    #[Test]
    public function aSeverityAFeedStatedIsNeverReplacedNorLookedUp(): void
    {
        $lookup = new SeverityLookupStub([self::CVE => Severity::Critical, 'CVE-2026-0002' => Severity::Critical]);

        $batch = $this->subject(
            $this->answering(['vendor/one' => [
                $this->unknown('UNRATED', self::CVE),
                AdvisoryBuilder::build(advisoryId: 'RATED-SAME-CVE', packageName: 'vendor/one', cve: self::CVE, severity: Severity::Medium),
                AdvisoryBuilder::build(advisoryId: 'RATED-OWN-CVE', packageName: 'vendor/one', cve: 'CVE-2026-0002', severity: Severity::Low),
            ]]),
            $lookup,
        )->advisoriesFor([$this->package('vendor/one')]);

        self::assertSame(
            ['UNRATED' => Severity::Critical, 'RATED-SAME-CVE' => Severity::Medium, 'RATED-OWN-CVE' => Severity::Low],
            $this->severitiesIn($batch->advisories),
        );
        self::assertSame([self::CVE], $lookup->lookedUp());
    }

    #[Test]
    public function anAdvisoryWithoutACveIsNotLookedUpAndTheBatchIsPassedOn(): void
    {
        $package = $this->package('vendor/one');
        $answer = new AdvisoryBatch([new AnsweredPackage($package, [$this->unknown('NO-CVE', '')])]);
        $lookup = new SeverityLookupStub();

        $batch = $this->subject(new PresetBatchAdvisorySource($answer), $lookup)->advisoriesFor([$package]);

        self::assertSame($answer, $batch);
        self::assertSame([], $lookup->lookedUp());
        self::assertSame([], $lookup->storedAskedFor(), 'Not even the cache is asked.');
    }

    #[Test]
    public function aCveSharedByTwoPackagesIsLookedUpOnceInUpperCase(): void
    {
        $one = $this->package('vendor/one');
        $two = $this->package('vendor/two');
        $lookup = new SeverityLookupStub([self::CVE => Severity::High]);

        $batch = $this->subject(
            $this->answering([
                'vendor/one' => [$this->unknown('ONE', self::CVE)],
                'vendor/two' => [$this->unknown('TWO', strtolower(self::CVE))],
            ]),
            $lookup,
        )->advisoriesFor([$one, $two]);

        self::assertSame([self::CVE], $lookup->lookedUp());
        self::assertSame([[self::CVE]], $lookup->storedAskedFor());
        self::assertSame(['ONE' => Severity::High], $this->severitiesIn($batch->advisoriesFor($one)));
        self::assertSame(['TWO' => Severity::High], $this->severitiesIn($batch->advisoriesFor($two)));
    }

    #[Test]
    public function aFailedLookupKeepsUnknownAddsNoFailureAndIsLogged(): void
    {
        $logger = new CollectingLogger();
        $lookup = new SeverityLookupStub([
            self::CVE => new SourceFailure('NVD', Ecosystem::Php, FailureReason::Rejected, 'NVD answered 404.'),
            'CVE-2026-0002' => Severity::High,
        ]);

        $batch = $this->subject(
            $this->answering(['vendor/one' => [$this->unknown('FAILED', self::CVE), $this->unknown('RATED', 'CVE-2026-0002')]]),
            $lookup,
            logger: $logger,
        )->advisoriesFor([$this->package('vendor/one')]);

        self::assertTrue($batch->isComplete());
        self::assertSame(['FAILED' => Severity::Unknown, 'RATED' => Severity::High], $this->severitiesIn($batch->advisories));
        self::assertSame([self::CVE, 'CVE-2026-0002'], $lookup->lookedUp(), 'A rejection does not stop the other lookups.');
        self::assertSame([[
            'level' => 'warning',
            'message' => 'Could not look up the severity of a CVE.',
            'context' => ['cve' => self::CVE, 'source' => 'NVD', 'reason' => 'rejected', 'detail' => 'NVD answered 404.'],
        ]], $logger->records());
    }

    #[Test]
    #[DataProvider('transientReasonProvider')]
    public function aTransientFailureStopsTheRemainingLookups(FailureReason $reason): void
    {
        $logger = new CollectingLogger();
        $lookup = new SeverityLookupStub([
            'CVE-2026-0001' => new SourceFailure('NVD', Ecosystem::Php, $reason, 'NVD did not answer.'),
            'CVE-2026-0002' => Severity::High,
            'CVE-2026-0003' => Severity::High,
        ]);

        $batch = $this->subject(
            $this->answering(['vendor/one' => [
                $this->unknown('A', 'CVE-2026-0001'),
                $this->unknown('B', 'CVE-2026-0002'),
                $this->unknown('C', 'CVE-2026-0003'),
            ]]),
            $lookup,
            logger: $logger,
        )->advisoriesFor([$this->package('vendor/one')]);

        self::assertSame(['CVE-2026-0001'], $lookup->lookedUp());
        self::assertSame(['A' => Severity::Unknown, 'B' => Severity::Unknown, 'C' => Severity::Unknown], $this->severitiesIn($batch->advisories));
        self::assertSame([], $batch->failures);
        self::assertSame(['warning', 'info'], array_column($logger->records(), 'level'));
        self::assertSame(['cves' => 2, 'maxLookupsPerBatch' => 5], $logger->records()[1]['context']);
    }

    /**
     * @return iterable<string, array{FailureReason}>
     */
    public static function transientReasonProvider(): iterable
    {
        yield 'rate limited' => [FailureReason::RateLimited];
        yield 'unreachable' => [FailureReason::Unreachable];
        yield 'timed out' => [FailureReason::Timeout];
    }

    #[Test]
    public function lookupsBeyondTheLimitStayUnknownAndAreLogged(): void
    {
        $logger = new CollectingLogger();
        $lookup = new SeverityLookupStub([
            'CVE-2026-0001' => Severity::Low,
            'CVE-2026-0002' => Severity::Medium,
            'CVE-2026-0003' => Severity::High,
        ]);

        $batch = $this->subject(
            $this->answering(['vendor/one' => [
                $this->unknown('A', 'CVE-2026-0001'),
                $this->unknown('B', 'CVE-2026-0002'),
                $this->unknown('C', 'CVE-2026-0003'),
            ]]),
            $lookup,
            maxLookupsPerBatch: 2,
            logger: $logger,
        )->advisoriesFor([$this->package('vendor/one')]);

        self::assertSame(['CVE-2026-0001', 'CVE-2026-0002'], $lookup->lookedUp());
        self::assertSame(['A' => Severity::Low, 'B' => Severity::Medium, 'C' => Severity::Unknown], $this->severitiesIn($batch->advisories));
        self::assertSame([[
            'level' => 'info',
            'message' => 'Left CVE severities unknown until a later batch.',
            'context' => ['cves' => 1, 'maxLookupsPerBatch' => 2],
        ]], $logger->records());
    }

    #[Test]
    public function fiveLookupsAreMadeByDefault(): void
    {
        $advisories = [];

        foreach (range(1, 6) as $number) {
            $advisories[] = $this->unknown('A' . $number, sprintf('CVE-2026-%04d', $number));
        }

        $lookup = new SeverityLookupStub();

        (new SeverityEnrichingAdvisorySource($this->answering(['vendor/one' => $advisories]), $lookup))
            ->advisoriesFor([$this->package('vendor/one')]);

        self::assertCount(5, $lookup->lookedUp());
    }

    #[Test]
    public function aStoredSeverityCostsNoLookup(): void
    {
        $logger = new CollectingLogger();
        $lookup = new SeverityLookupStub(
            answers: ['CVE-2026-0001' => Severity::Low, 'CVE-2026-0003' => Severity::High],
            stored: ['CVE-2026-0002' => Severity::Critical],
        );

        $batch = $this->subject(
            $this->answering(['vendor/one' => [
                $this->unknown('A', 'CVE-2026-0001'),
                $this->unknown('B', 'CVE-2026-0002'),
                $this->unknown('C', 'CVE-2026-0003'),
            ]]),
            $lookup,
            maxLookupsPerBatch: 1,
            logger: $logger,
        )->advisoriesFor([$this->package('vendor/one')]);

        self::assertSame(['CVE-2026-0001'], $lookup->lookedUp());
        self::assertSame(['A' => Severity::Low, 'B' => Severity::Critical, 'C' => Severity::Unknown], $this->severitiesIn($batch->advisories));
        self::assertSame(['cves' => 1, 'maxLookupsPerBatch' => 1], $logger->records()[0]['context']);
    }

    #[Test]
    public function aStoredSeverityIsStillReadAfterATransientFailure(): void
    {
        $lookup = new SeverityLookupStub(
            answers: ['CVE-2026-0001' => new SourceFailure('NVD', Ecosystem::Php, FailureReason::RateLimited, 'Slow down.')],
            stored: ['CVE-2026-0002' => Severity::Medium],
        );

        $batch = $this->subject(
            $this->answering(['vendor/one' => [$this->unknown('A', 'CVE-2026-0001'), $this->unknown('B', 'CVE-2026-0002')]]),
            $lookup,
        )->advisoriesFor([$this->package('vendor/one')]);

        self::assertSame(['A' => Severity::Unknown, 'B' => Severity::Medium], $this->severitiesIn($batch->advisories));
    }

    #[Test]
    public function aLimitOfZeroUsesStoredSeveritiesAlone(): void
    {
        $lookup = new SeverityLookupStub(
            answers: ['CVE-2026-0001' => Severity::Low],
            stored: ['CVE-2026-0002' => Severity::Critical],
        );

        $batch = $this->subject(
            $this->answering(['vendor/one' => [$this->unknown('A', 'CVE-2026-0001'), $this->unknown('B', 'CVE-2026-0002')]]),
            $lookup,
            maxLookupsPerBatch: 0,
        )->advisoriesFor([$this->package('vendor/one')]);

        self::assertSame([], $lookup->lookedUp());
        self::assertSame(['A' => Severity::Unknown, 'B' => Severity::Critical], $this->severitiesIn($batch->advisories));
    }

    #[Test]
    public function aNegativeLimitIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->subject($this->answering([]), new SeverityLookupStub(), maxLookupsPerBatch: -1);
    }

    #[Test]
    public function theInnerSourcesFailuresAndUnansweredPackagesPassThrough(): void
    {
        $answered = $this->package('vendor/one');
        $unanswered = $this->package('vendor/two');
        $failure = new SourceFailure('Packagist', Ecosystem::Composer, FailureReason::Timeout, 'Timed out.');
        $inner = new PresetBatchAdvisorySource(new AdvisoryBatch(
            answeredFor: [new AnsweredPackage($answered, [$this->unknown('A', self::CVE)])],
            failures: [$failure],
        ));

        $batch = $this->subject($inner, new SeverityLookupStub([self::CVE => Severity::High]))
            ->advisoriesFor([$answered, $unanswered]);

        self::assertSame([$failure], $batch->failures);
        self::assertSame(['A' => Severity::High], $this->severitiesIn($batch->advisoriesFor($answered)));
        self::assertFalse($batch->wasAnsweredFor($unanswered));
    }

    #[Test]
    public function nameAndCoverageAreTheInnerSources(): void
    {
        $subject = $this->subject(new StubAdvisorySource('Packagist', [Ecosystem::Composer, Ecosystem::Npm]), new SeverityLookupStub());

        self::assertSame('Packagist', $subject->name());
        self::assertSame([Ecosystem::Composer, Ecosystem::Npm], $subject->coveredEcosystems());
    }

    private function subject(
        AdvisorySource $inner,
        SeverityLookupStub $lookup,
        int $maxLookupsPerBatch = 5,
        CollectingLogger $logger = new CollectingLogger(),
    ): SeverityEnrichingAdvisorySource {
        return new SeverityEnrichingAdvisorySource($inner, $lookup, $maxLookupsPerBatch, $logger);
    }

    /**
     * @param array<string, list<Advisory>> $advisoriesByPackageName
     */
    private function answering(array $advisoriesByPackageName): StubAdvisorySource
    {
        return new StubAdvisorySource('Packagist', [Ecosystem::Composer], $advisoriesByPackageName);
    }

    private function unknown(string $advisoryId, string $cve): Advisory
    {
        return AdvisoryBuilder::build(advisoryId: $advisoryId, cve: $cve, severity: Severity::Unknown);
    }

    private function package(string $name): PackageRef
    {
        return new PackageRef(PackageUrl::fromPackageName('composer', $name), '1.0.0');
    }

    /**
     * @param list<Advisory> $advisories
     * @return array<string, Severity>
     */
    private function severitiesIn(array $advisories): array
    {
        $severities = [];

        foreach ($advisories as $advisory) {
            $severities[$advisory->advisoryId] = $advisory->severity;
        }

        return $severities;
    }
}
