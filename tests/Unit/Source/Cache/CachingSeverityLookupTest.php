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

use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\Cache\CachingSeverityLookup;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use mteu\AdvisoryMatcher\Tests\Unit\Source\Http\CollectingLogger;
use mteu\AdvisoryMatcher\Tests\Unit\Source\SeverityLookupStub;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(CachingSeverityLookup::class)]
final class CachingSeverityLookupTest extends TestCase
{
    private const string CVE = 'CVE-2026-109162';

    #[Test]
    public function aKnownSeverityIsKeptForSevenDays(): void
    {
        $cache = new SimpleCacheDouble();
        $inner = new SeverityLookupStub([self::CVE => Severity::Critical]);
        $subject = new CachingSeverityLookup($inner, $cache);

        self::assertSame(Severity::Critical, $subject->severityForCve(self::CVE));
        self::assertSame(Severity::Critical, $subject->severityForCve(self::CVE));

        self::assertSame([self::CVE], $inner->lookedUp());
        self::assertSame([self::keyFor(self::CVE)], $cache->storedKeys());
        self::assertSame('critical', $cache->get(self::keyFor(self::CVE)));
        self::assertSame(604800, $cache->ttlOf(self::keyFor(self::CVE)));
    }

    #[Test]
    public function anUnknownSeverityIsKeptForOneDayOnly(): void
    {
        $cache = new SimpleCacheDouble();
        $inner = new SeverityLookupStub();
        $subject = new CachingSeverityLookup($inner, $cache);

        self::assertSame(Severity::Unknown, $subject->severityForCve(self::CVE));
        self::assertSame(Severity::Unknown, $subject->severityForCve(self::CVE));

        self::assertSame([self::CVE], $inner->lookedUp());
        self::assertSame('unknown', $cache->get(self::keyFor(self::CVE)));
        self::assertSame(86400, $cache->ttlOf(self::keyFor(self::CVE)));
    }

    #[Test]
    public function aFailureIsNeverCached(): void
    {
        $cache = new SimpleCacheDouble();
        $failure = new SourceFailure('NVD', Ecosystem::Php, FailureReason::RateLimited, 'Slow down.', 30);
        $inner = new SeverityLookupStub([self::CVE => $failure]);
        $subject = new CachingSeverityLookup($inner, $cache);

        self::assertSame($failure, $subject->severityForCve(self::CVE));
        self::assertSame($failure, $subject->severityForCve(self::CVE));

        self::assertSame([self::CVE, self::CVE], $inner->lookedUp());
        self::assertSame([], $cache->storedKeys());
    }

    #[Test]
    public function theKeyIgnoresTheCaseOfTheId(): void
    {
        $cache = new SimpleCacheDouble();
        $inner = new SeverityLookupStub(['cve-2026-109162' => Severity::High]);
        $subject = new CachingSeverityLookup($inner, $cache);

        $subject->severityForCve('cve-2026-109162');

        self::assertSame([self::CVE => Severity::High], $subject->storedSeveritiesForCves([self::CVE]));
        self::assertSame([self::keyFor(self::CVE)], $cache->storedKeys());
    }

    #[Test]
    public function theKeyIsPsr16SafeWhateverTheIdHolds(): void
    {
        $cache = new SimpleCacheDouble();

        (new CachingSeverityLookup(new SeverityLookupStub(), $cache))->severityForCve('{CVE}(2026)/\\@:');

        self::assertMatchesRegularExpression('/^cve_severity_v1_[0-9a-f]{40}$/D', $cache->storedKeys()[0]);
    }

    #[Test]
    public function aStoredSeverityIsReadWithoutAskingTheInnerLookup(): void
    {
        $cache = new SimpleCacheDouble();
        $cache->set(self::keyFor(self::CVE), 'medium');
        $inner = new SeverityLookupStub([self::CVE => Severity::Critical], stored: [self::CVE => Severity::Low]);
        $subject = new CachingSeverityLookup($inner, $cache);

        self::assertSame([self::CVE => Severity::Medium], $subject->storedSeveritiesForCves([self::CVE]));
        self::assertSame(Severity::Medium, $subject->severityForCve(self::CVE));
        self::assertSame([], $inner->lookedUp());
    }

    #[Test]
    public function withNothingCachedTheInnerLookupsStoredSeverityIsRead(): void
    {
        $subject = new CachingSeverityLookup(
            new SeverityLookupStub(stored: [self::CVE => Severity::Low]),
            new SimpleCacheDouble(),
        );

        self::assertSame([self::CVE => Severity::Low], $subject->storedSeveritiesForCves([self::CVE, 'CVE-2026-0001']));
    }

    #[Test]
    public function idsTheCacheLacksAreAskedOfTheInnerLookupInOneList(): void
    {
        $cache = new SimpleCacheDouble();
        $cache->set(self::keyFor('CVE-2026-0001'), 'high');
        $inner = new SeverityLookupStub(stored: ['CVE-2026-0002' => Severity::Low]);
        $subject = new CachingSeverityLookup($inner, $cache);

        self::assertSame(
            ['CVE-2026-0001' => Severity::High, 'CVE-2026-0002' => Severity::Low],
            $subject->storedSeveritiesForCves(['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003']),
        );
        self::assertSame([['CVE-2026-0002', 'CVE-2026-0003']], $inner->storedAskedFor());
        self::assertSame([], $inner->lookedUp());
    }

    #[Test]
    public function anUnreadableEntryIsAskedAgainAndOverwritten(): void
    {
        foreach (['severe', 3] as $unreadable) {
            $cache = new SimpleCacheDouble();
            $cache->set(self::keyFor(self::CVE), $unreadable);
            $inner = new SeverityLookupStub([self::CVE => Severity::High]);
            $subject = new CachingSeverityLookup($inner, $cache);

            self::assertSame([], $subject->storedSeveritiesForCves([self::CVE]));
            self::assertSame(Severity::High, $subject->severityForCve(self::CVE));
            self::assertSame('high', $cache->get(self::keyFor(self::CVE)));
        }
    }

    #[Test]
    public function aRefusedWriteIsLoggedAndTheSeverityStillReturned(): void
    {
        $cache = new SimpleCacheDouble();
        $cache->refuseWrites();
        $logger = new CollectingLogger();

        $severity = (new CachingSeverityLookup(new SeverityLookupStub([self::CVE => Severity::High]), $cache, $logger))
            ->severityForCve(self::CVE);

        self::assertSame(Severity::High, $severity);
        self::assertSame([[
            'level' => 'warning',
            'message' => 'Could not store a CVE severity.',
            'context' => ['cve' => self::CVE],
        ]], $logger->records());
    }

    #[Test]
    public function aStoredWriteLogsNothing(): void
    {
        $logger = new CollectingLogger();

        (new CachingSeverityLookup(new SeverityLookupStub(), new SimpleCacheDouble(), $logger))->severityForCve(self::CVE);

        self::assertSame([], $logger->records());
    }

    private static function keyFor(string $cveId): string
    {
        return 'cve_severity_v1_' . sha1($cveId);
    }
}
