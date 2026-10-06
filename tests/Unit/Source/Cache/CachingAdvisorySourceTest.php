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

namespace mteu\AdvisoryMatcher\Tests\Unit\Source\Cache;

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\Cache\CachedAnswerCodec;
use mteu\AdvisoryMatcher\Source\Cache\CachingAdvisorySource;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Tests\Unit\Advisory\AdvisoryBuilder;
use mteu\AdvisoryMatcher\Tests\Unit\Source\Http\CollectingLogger;
use mteu\AdvisoryMatcher\Tests\Unit\Source\StubAdvisorySource;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(CachingAdvisorySource::class)]
final class CachingAdvisorySourceTest extends TestCase
{
    private SimpleCacheDouble $cache;

    private RecordingAdvisorySource $inner;

    protected function setUp(): void
    {
        $this->cache = new SimpleCacheDouble();
        $this->inner = new RecordingAdvisorySource();
    }

    #[Test]
    public function anEmptyQuestionNeverReachesTheInnerSource(): void
    {
        $batch = $this->subject()->advisoriesFor([]);

        self::assertSame([], $this->inner->calls());
        self::assertSame([], $batch->answeredFor);
    }

    #[Test]
    public function packagesOutsideTheCoveredEcosystemsAreNeitherAskedAboutNorFailed(): void
    {
        $npm = new PackageRef(Ecosystem::Npm, 'lodash', '4.17.20');

        $batch = $this->subject()->advisoriesFor([$npm]);

        self::assertSame([], $this->inner->calls());
        self::assertFalse($batch->wasAnsweredFor($npm));
        self::assertTrue($batch->isComplete());
    }

    #[Test]
    public function theDecoratorNamesItselfAndRoutesAsTheSourceItWraps(): void
    {
        $subject = $this->subject();

        self::assertSame('Recorded', $subject->name());
        self::assertSame([Ecosystem::Composer], $subject->coveredEcosystems());
    }

    #[Test]
    public function aCachedPackageIsAnsweredWithoutCallingTheInnerSource(): void
    {
        $subject = $this->subject();
        $package = $this->package('vendor/example');

        $subject->advisoriesFor([$package]);
        $batch = $subject->advisoriesFor([$package]);

        self::assertCount(1, $this->inner->calls());
        self::assertTrue($batch->wasAnsweredFor($package));
        self::assertTrue($batch->isComplete());
    }

    #[Test]
    public function addingAPackageOnlyFetchesTheNewOne(): void
    {
        $subject = $this->subject();

        $subject->advisoriesFor([$this->package('vendor/one'), $this->package('vendor/two')]);
        $subject->advisoriesFor([
            $this->package('vendor/one'),
            $this->package('vendor/two'),
            $this->package('vendor/three'),
        ]);

        self::assertSame([['vendor/one', 'vendor/two'], ['vendor/three']], $this->inner->calls());
    }

    #[Test]
    public function aFetchedPackageIsCombinedWithTheOnesAnsweredFromCache(): void
    {
        $this->inner
            ->withAdvisories('vendor/one', [$this->advisory('vendor/one', 'CVE-2026-0001')])
            ->withAdvisories('vendor/two', [$this->advisory('vendor/two', 'CVE-2026-0002')]);
        $subject = $this->subject();
        $one = $this->package('vendor/one');
        $two = $this->package('vendor/two');

        $subject->advisoriesFor([$one]);
        $batch = $subject->advisoriesFor([$one, $two]);

        self::assertSame([['vendor/one'], ['vendor/two']], $this->inner->calls());
        self::assertCount(1, $batch->advisoriesFor($one));
        self::assertCount(1, $batch->advisoriesFor($two));
    }

    #[Test]
    public function aCachedAdvisoryComesBackAsItWasFetched(): void
    {
        $advisory = $this->advisory('vendor/one', 'CVE-2026-0001');
        $this->inner->withAdvisories('vendor/one', [$advisory]);
        $subject = $this->subject();
        $package = $this->package('vendor/one');

        $subject->advisoriesFor([$package]);

        self::assertEquals([$advisory], $subject->advisoriesFor([$package])->advisories);
    }

    #[Test]
    public function eachVersionIsCachedWithItsOwnAnswer(): void
    {
        $newer = new PackageRef(Ecosystem::Php, 'php', '8.3.14');
        $older = new PackageRef(Ecosystem::Php, 'php', '8.2.10');
        $forNewer = AdvisoryBuilder::build(packageName: 'php', ecosystem: Ecosystem::Php, firstPatchedVersion: '8.3.15');
        $forOlder = AdvisoryBuilder::build(packageName: 'php', ecosystem: Ecosystem::Php, firstPatchedVersion: '8.2.27');
        $inner = (new RecordingAdvisorySource([Ecosystem::Php]))
            ->withAdvisoriesAt('php', '8.3.14', [$forNewer])
            ->withAdvisoriesAt('php', '8.2.10', [$forOlder]);
        $subject = new CachingAdvisorySource($inner, $this->cache);

        $fetched = $subject->advisoriesFor([$newer, $older]);
        $cached = $subject->advisoriesFor([$newer, $older]);

        self::assertCount(1, $inner->calls());
        foreach ([$fetched, $cached] as $batch) {
            self::assertEquals([$forNewer], $batch->advisoriesFor($newer));
            self::assertEquals([$forOlder], $batch->advisoriesFor($older));
        }
    }

    #[Test]
    public function theAnswersOfOneFetchAreStoredInOneWriteWithTheConfiguredTtl(): void
    {
        $packages = [$this->package('vendor/one'), $this->package('vendor/two'), $this->package('vendor/three')];

        (new CachingAdvisorySource($this->inner, $this->cache, ttlSeconds: 900))->advisoriesFor($packages);

        self::assertSame(1, $this->cache->writeCalls());
        self::assertCount(3, $this->cache->storedKeys());
        foreach ($this->cache->storedKeys() as $key) {
            self::assertSame(900, $this->cache->ttlOf($key));
        }
    }

    #[Test]
    public function aTtlBelowOneSecondIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new CachingAdvisorySource($this->inner, $this->cache, ttlSeconds: 0);
    }

    #[Test]
    public function aRefusedWriteIsLoggedWithTheSourceAndTheEntryCount(): void
    {
        $this->cache->refuseWrites();
        $logger = new CollectingLogger();
        $packages = [$this->package('vendor/one'), $this->package('vendor/two')];

        $batch = (new CachingAdvisorySource($this->inner, $this->cache, logger: $logger))->advisoriesFor($packages);

        self::assertTrue($batch->wasAnsweredFor($packages[0]));
        self::assertCount(1, $logger->records());
        self::assertSame('warning', $logger->records()[0]['level']);
        self::assertSame(['source' => 'Recorded', 'entries' => 2], $logger->records()[0]['context']);
    }

    #[Test]
    public function aFailedFetchLeavesThePackageUnansweredAndIsNotCached(): void
    {
        $this->inner->failingWith(FailureReason::Unreachable);
        $package = $this->package('vendor/example');

        $batch = $this->subject()->advisoriesFor([$package]);

        self::assertFalse($batch->wasAnsweredFor($package));
        self::assertSame(FailureReason::Unreachable, $batch->failures[0]->reason);
        self::assertSame([], $this->cache->storedKeys());
    }

    #[Test]
    public function aPackageTheFeedDoesNotKnowIsUnansweredWithoutAFailureAndNotCached(): void
    {
        $this->inner->notKnowing('vendor/private');
        $package = $this->package('vendor/private');

        $batch = $this->subject()->advisoriesFor([$package]);

        self::assertFalse($batch->wasAnsweredFor($package));
        self::assertTrue($batch->isComplete());
        self::assertSame([], $this->cache->storedKeys());
    }

    #[Test]
    public function aCachedEntryCarryingAnUnsafeLinkIsDroppedAndThePackageFetchedAgain(): void
    {
        $package = $this->package('vendor/example');
        $this->subject()->advisoriesFor([$package]);
        $key = $this->cache->storedKeys()[0];
        $entry = (new CachedAnswerCodec())->encode([$this->advisory('vendor/example', 'CVE-2026-0001')]);
        $entry[0]['link'] = 'javascript:alert(document.cookie)';
        $this->cache->set($key, $entry);

        $batch = $this->subject()->advisoriesFor([$package]);

        self::assertCount(2, $this->inner->calls());
        self::assertSame([], $batch->advisoriesFor($package));
    }

    #[Test]
    public function anUnreadableEntryIsDroppedAndThePackageFetchedAgain(): void
    {
        $package = $this->package('vendor/example');
        $this->subject()->advisoriesFor([$package]);
        $key = $this->cache->storedKeys()[0];
        $this->cache->set($key, ['not' => 'an entry']);

        $batch = $this->subject()->advisoriesFor([$package]);

        self::assertCount(2, $this->inner->calls());
        self::assertTrue($batch->wasAnsweredFor($package));
        self::assertSame([], $this->cache->get($key));
    }

    #[Test]
    public function twoSourcesSharingOneCacheNeverReadEachOthersEntries(): void
    {
        $package = $this->package('vendor/example');
        $this->subject()->advisoriesFor([$package]);
        $otherInner = new StubAdvisorySource('OSV', [Ecosystem::Composer]);

        (new CachingAdvisorySource($otherInner, $this->cache))->advisoriesFor([$package]);

        self::assertSame([$package], $otherInner->askedAbout());
    }

    private function subject(): CachingAdvisorySource
    {
        return new CachingAdvisorySource($this->inner, $this->cache);
    }

    private function package(string $name): PackageRef
    {
        return new PackageRef(Ecosystem::Composer, $name, '1.0.0');
    }

    private function advisory(string $packageName, string $cve): Advisory
    {
        return AdvisoryBuilder::build(
            advisoryId: 'PKSA-' . $cve,
            packageName: $packageName,
            remoteId: 'GHSA-' . $cve,
            cve: $cve,
            firstPatchedVersion: '2.0.0',
        );
    }
}
