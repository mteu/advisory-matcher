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

use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\AnsweredPackage;
use mteu\AdvisoryMatcher\Source\CompositeAdvisorySource;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use mteu\AdvisoryMatcher\Tests\Unit\Advisory\AdvisoryBuilder;
use mteu\AdvisoryMatcher\Tests\Unit\Source\Http\CollectingLogger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(CompositeAdvisorySource::class)]
final class CompositeAdvisorySourceTest extends TestCase
{
    #[Test]
    public function coverageIsTheUnionOfItsSourcesEachEcosystemOnce(): void
    {
        $composite = new CompositeAdvisorySource([
            new StubAdvisorySource('Packagist', [Ecosystem::Composer]),
            new StubAdvisorySource('OSV', [Ecosystem::Composer, Ecosystem::Npm]),
            new StubAdvisorySource('NVD', [Ecosystem::Php]),
        ]);

        self::assertSame([Ecosystem::Composer, Ecosystem::Npm, Ecosystem::Php], $composite->coveredEcosystems());
    }

    #[Test]
    public function aPackageGoesOnlyToTheSourcesCoveringItsEcosystem(): void
    {
        $composer = $this->composer('vendor/one');
        $npm = $this->npm('lodash');
        $packagist = new StubAdvisorySource('Packagist', [Ecosystem::Composer]);
        $osv = new StubAdvisorySource('OSV', [Ecosystem::Npm]);

        (new CompositeAdvisorySource([$packagist, $osv]))->advisoriesFor([$composer, $npm]);

        self::assertSame([$composer], $packagist->askedAbout());
        self::assertSame([$npm], $osv->askedAbout());
    }

    #[Test]
    public function eachSourceIsCalledOnceWithItsWholeSubset(): void
    {
        $packagist = new StubAdvisorySource('Packagist', [Ecosystem::Composer]);
        $one = $this->composer('vendor/one');
        $two = $this->composer('vendor/two');

        (new CompositeAdvisorySource([$packagist]))->advisoriesFor([$one, $this->npm('lodash'), $two]);

        self::assertSame(1, $packagist->timesAsked());
        self::assertSame([$one, $two], $packagist->askedAbout());
    }

    #[Test]
    public function aSourceCoveringNothingItWasHandedIsNeverCalled(): void
    {
        $npmOnly = new StubAdvisorySource('OSV', [Ecosystem::Npm]);

        (new CompositeAdvisorySource([
            new StubAdvisorySource('Packagist', [Ecosystem::Composer]),
            $npmOnly,
        ]))->advisoriesFor([$this->composer('vendor/one')]);

        self::assertSame(0, $npmOnly->timesAsked());
    }

    #[Test]
    public function anEmptyAskCallsNoSourceAndIsComplete(): void
    {
        $packagist = new StubAdvisorySource('Packagist', [Ecosystem::Composer]);

        $batch = (new CompositeAdvisorySource([$packagist]))->advisoriesFor([]);

        self::assertSame(0, $packagist->timesAsked());
        self::assertTrue($batch->isComplete());
        self::assertSame([], $batch->answeredFor);
    }

    #[Test]
    public function aPackageNoSourceCoversIsNeitherAnsweredNorAFailure(): void
    {
        $lodash = $this->npm('lodash');

        $batch = (new CompositeAdvisorySource([
            new StubAdvisorySource('Packagist', [Ecosystem::Composer]),
        ]))->advisoriesFor([$lodash]);

        self::assertFalse($batch->wasAnsweredFor($lodash));
        self::assertTrue($batch->isComplete());
    }

    #[Test]
    public function answeredForIsTheUnionOfEverySourcesAnswers(): void
    {
        $composer = $this->composer('vendor/one');
        $npm = $this->npm('lodash');

        $batch = (new CompositeAdvisorySource([
            new StubAdvisorySource('Packagist', [Ecosystem::Composer]),
            new StubAdvisorySource('OSV', [Ecosystem::Npm]),
        ]))->advisoriesFor([$composer, $npm]);

        self::assertSame(
            [$composer->identity(), $npm->identity()],
            array_map(static fn (AnsweredPackage $answer): string => $answer->package->identity(), $batch->answeredFor),
        );
    }

    #[Test]
    public function oneVulnerabilityFromTwoSourcesCollapsesToTheUnionConstraintAndHigherSeverity(): void
    {
        $package = $this->composer('vendor/one');

        $composite = new CompositeAdvisorySource([
            new StubAdvisorySource('Packagist', [Ecosystem::Composer], ['vendor/one' => [AdvisoryBuilder::build(
                advisoryId: 'PKSA-aaaa-bbbb-cccc',
                packageName: 'vendor/one',
                cve: 'CVE-2026-0001',
                affectedVersions: '>=1.0.0,<1.2.0',
                severity: Severity::Medium,
            )]]),
            new StubAdvisorySource('OSV', [Ecosystem::Composer], ['vendor/one' => [AdvisoryBuilder::build(
                advisoryId: 'OSV-GHSA-xxxx-yyyy-zzzz',
                packageName: 'vendor/one',
                cve: 'CVE-2026-0001',
                affectedVersions: '>=2.0.0,<2.1.0',
                severity: Severity::Critical,
            )]]),
        ]);

        $advisories = $composite->advisoriesFor([$package])->advisoriesFor($package);

        self::assertCount(1, $advisories);
        self::assertSame('>=1.0.0,<1.2.0 || >=2.0.0,<2.1.0', $advisories[0]->affectedVersions->toComposerConstraint());
        self::assertSame(Severity::Critical, $advisories[0]->severity);
    }

    #[Test]
    public function everyFailureOfEverySourceIsCarriedAndTheBatchIsIncomplete(): void
    {
        $composer = $this->composer('vendor/one');
        $npm = $this->npm('lodash');

        $batch = (new CompositeAdvisorySource([
            new FailingAdvisorySource('Packagist', [Ecosystem::Composer]),
            new FailingAdvisorySource('OSV', [Ecosystem::Npm], FailureReason::RateLimited),
        ]))->advisoriesFor([$composer, $npm]);

        self::assertFalse($batch->isComplete());
        self::assertSame(
            ['Packagist composer unreachable', 'OSV npm rate_limited'],
            array_map(
                static fn (SourceFailure $failure): string => sprintf(
                    '%s %s %s',
                    $failure->sourceName,
                    $failure->ecosystem->value,
                    $failure->reason->value,
                ),
                $batch->failures,
            ),
        );
    }

    /**
     * @return iterable<string, array{\Throwable}>
     */
    public static function defects(): iterable
    {
        yield 'a logic exception' => [new \LogicException('state went missing')];
        yield 'a runtime exception' => [new \RuntimeException('the feed client gave up')];
    }

    /**
     * @return iterable<string, array{\Error}>
     */
    public static function programmingErrors(): iterable
    {
        yield 'a type error' => [new \TypeError('Argument #1 must be of type string, null given')];
        yield 'an argument count error' => [new \ArgumentCountError('Too few arguments to function Feed::read(), 0 passed')];
        yield 'a call to an undefined method' => [new \Error('Call to undefined method Feed::fetch()')];
    }

    #[Test]
    #[DataProvider('defects')]
    public function aSourceThatThrowsBecomesABrokenFailureAndTheOthersStillAnswer(\Throwable $defect): void
    {
        $composer = $this->composer('vendor/one');
        $npm = $this->npm('lodash');

        $batch = (new CompositeAdvisorySource([
            new ThrowingAdvisorySource('Packagist', [Ecosystem::Composer], $defect),
            new StubAdvisorySource('OSV', [Ecosystem::Npm], ['lodash' => [
                AdvisoryBuilder::build(advisoryId: 'OSV-GHSA-npm', packageName: 'lodash', ecosystem: Ecosystem::Npm),
            ]]),
        ]))->advisoriesFor([$composer, $npm]);

        self::assertTrue($batch->wasAnsweredFor($npm));
        self::assertCount(1, $batch->advisoriesFor($npm));
        self::assertFalse($batch->wasAnsweredFor($composer));

        self::assertFalse($batch->isComplete());
        self::assertCount(1, $batch->failures);
        self::assertSame('Packagist', $batch->failures[0]->sourceName);
        self::assertSame(Ecosystem::Composer, $batch->failures[0]->ecosystem);
        self::assertSame(FailureReason::Broken, $batch->failures[0]->reason);
        self::assertFalse($batch->failures[0]->reason->isTransient());
        self::assertStringContainsString($defect->getMessage(), $batch->failures[0]->detail);
    }

    #[Test]
    #[DataProvider('programmingErrors')]
    public function anErrorFromASourceBubblesRatherThanBecomingAFailure(\Error $error): void
    {
        $logger = new CollectingLogger();
        $composite = new CompositeAdvisorySource(
            [new ThrowingAdvisorySource('Packagist', [Ecosystem::Composer], $error)],
            $logger,
        );

        try {
            $composite->advisoriesFor([$this->composer('vendor/one')]);
            self::fail('The error was caught.');
        } catch (\Error $caught) {
            self::assertSame($error, $caught);
        }

        self::assertSame([], $logger->records());
    }

    #[Test]
    public function aThrowerIsFiledOnceForEachEcosystemItWasAskedAbout(): void
    {
        $batch = (new CompositeAdvisorySource([
            new ThrowingAdvisorySource(
                'OSV',
                [Ecosystem::Composer, Ecosystem::Npm],
                new \LogicException('broken'),
            ),
        ]))->advisoriesFor([
            $this->npm('lodash'),
            $this->composer('vendor/one'),
            $this->npm('express'),
        ]);

        self::assertSame(
            [Ecosystem::Npm, Ecosystem::Composer],
            array_map(static fn (SourceFailure $failure): Ecosystem => $failure->ecosystem, $batch->failures),
        );
    }

    #[Test]
    public function aThrowerIsLoggedByMessageAndNeverByTheExceptionObject(): void
    {
        $logger = new CollectingLogger();
        $defect = new \LogicException('state went missing');

        (new CompositeAdvisorySource(
            [new ThrowingAdvisorySource('Packagist', [Ecosystem::Composer], $defect)],
            $logger,
        ))->advisoriesFor([$this->composer('vendor/one')]);

        $records = $logger->records();
        self::assertCount(1, $records);
        self::assertSame('error', $records[0]['level']);
        self::assertSame('Packagist', $records[0]['context']['source']);
        self::assertSame('state went missing', $records[0]['context']['message']);

        foreach ($records[0]['context'] as $value) {
            self::assertNotInstanceOf(\Throwable::class, $value);
        }
    }

    #[Test]
    public function aFailedSourceDoesNotSendItsPackagesToAnotherSource(): void
    {
        $composer = $this->composer('vendor/one');
        $npm = $this->npm('lodash');
        $packagist = new FailingAdvisorySource('Packagist', [Ecosystem::Composer]);
        $osv = new StubAdvisorySource('OSV', [Ecosystem::Npm]);

        $batch = (new CompositeAdvisorySource([$packagist, $osv]))->advisoriesFor([$composer, $npm]);

        self::assertSame(1, $packagist->timesAsked());
        self::assertSame([$npm], $osv->askedAbout());
        self::assertFalse($batch->wasAnsweredFor($composer));
    }

    #[Test]
    public function aCompositeNestsInsideAnotherComposite(): void
    {
        $inner = new CompositeAdvisorySource([new StubAdvisorySource('Packagist', [Ecosystem::Composer])]);
        $outer = new CompositeAdvisorySource([$inner]);
        $package = $this->composer('vendor/one');

        self::assertSame('Composite', $outer->name());
        self::assertTrue($outer->advisoriesFor([$package])->wasAnsweredFor($package));
    }

    private function composer(string $name): PackageRef
    {
        return new PackageRef(Ecosystem::Composer, $name, '1.0.0');
    }

    private function npm(string $name): PackageRef
    {
        return new PackageRef(Ecosystem::Npm, $name, '4.17.20');
    }
}
