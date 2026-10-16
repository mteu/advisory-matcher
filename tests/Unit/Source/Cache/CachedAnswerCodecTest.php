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
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Advisory\AdvisoryReference;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\Cache\CachedAnswerCodec;
use mteu\AdvisoryMatcher\Source\Cache\UnreadableCacheEntry;
use mteu\AdvisoryMatcher\Tests\Unit\Advisory\AdvisoryBuilder;
use mteu\AdvisoryMatcher\Version\AffectedVersions;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(CachedAnswerCodec::class)]
#[CoversClass(UnreadableCacheEntry::class)]
final class CachedAnswerCodecTest extends TestCase
{
    #[Test]
    public function encodedAdvisoriesDecodeToTheSameAdvisories(): void
    {
        $advisory = new Advisory(
            advisoryId: 'PKSA-dmw8-jd8k-q3c6',
            package: PackageUrl::fromPackageName('composer', 'monolog/monolog'),
            title: 'Header injection in NativeMailerHandler',
            link: 'https://github.com/Seldaek/monolog/pull/448',
            cve: '',
            affectedVersions: AffectedVersions::fromComposerConstraint('>=1.8.0,<1.12.0'),
            reportedAt: new \DateTimeImmutable('2014-12-29T00:00:00+00:00'),
            severity: Severity::Low,
            references: [new AdvisoryReference('GitHub', 'GHSA-f57v-q966-7fh6')],
            firstPatchedVersion: '1.12.0',
        );
        $codec = new CachedAnswerCodec();

        self::assertEquals([$advisory], $codec->decode($codec->encode([$advisory])));
    }

    #[Test]
    public function anAnswerWithNoAdvisoriesDecodesToNoAdvisories(): void
    {
        $codec = new CachedAnswerCodec();

        self::assertSame([], $codec->decode($codec->encode([])));
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function entriesThisCodecDidNotWrite(): iterable
    {
        yield 'not an array' => ['[]'];
        yield 'not a list' => [['advisories' => []]];
        yield 'an advisory that is not a record' => [['PKSA-1']];
        yield 'an advisory missing a field' => [[['advisoryId' => 'PKSA-1']]];
    }

    #[Test]
    #[DataProvider('entriesThisCodecDidNotWrite')]
    public function anEntryItDidNotWriteIsRefused(mixed $entry): void
    {
        $this->expectException(UnreadableCacheEntry::class);

        (new CachedAnswerCodec())->decode($entry);
    }

    #[Test]
    public function anAdvisoryWithAnUnknownSeverityIsRefused(): void
    {
        $codec = new CachedAnswerCodec();
        $entry = $codec->encode([new Advisory(
            advisoryId: 'PKSA-1',
            package: PackageUrl::fromPackageName('npm', 'vendor/one'),
            title: 'A vulnerability',
            link: '',
            cve: '',
            affectedVersions: AffectedVersions::fromComposerConstraint('<1.0.0'),
            reportedAt: new \DateTimeImmutable('2026-01-01T00:00:00+00:00'),
            severity: Severity::High,
            references: [],
        )]);
        $entry[0]['severity'] = 'catastrophic';

        $this->expectException(UnreadableCacheEntry::class);

        $codec->decode($entry);
    }

    #[Test]
    public function anAdvisoryBreakingAnInvariantIsRefusedAsUnreadable(): void
    {
        $codec = new CachedAnswerCodec();
        $entry = $codec->encode([AdvisoryBuilder::build()]);
        $entry[0]['link'] = 'javascript:alert(1)';

        try {
            $codec->decode($entry);
            self::fail('An advisory with a javascript: link was rebuilt from the cache.');
        } catch (UnreadableCacheEntry $exception) {
            self::assertInstanceOf(\InvalidArgumentException::class, $exception->getPrevious());
        }
    }

    #[Test]
    public function thePackageUrlSurvivesTheRoundTrip(): void
    {
        $codec = new CachedAnswerCodec();
        $advisories = [AdvisoryBuilder::build(packageName: 'JSONStream', ecosystem: Ecosystem::Npm)];

        $decoded = $codec->decode($codec->encode($advisories))[0];

        self::assertSame('pkg:npm/JSONStream', $decoded->package->toString());
        self::assertSame(Ecosystem::Npm, $decoded->ecosystem);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function unreadablePackageUrls(): iterable
    {
        yield 'not a package URL' => ['vendor/one'];
        yield 'not a string' => [42];
        yield 'no package URL, as an entry written before it existed' => [null];
    }

    #[Test]
    #[DataProvider('unreadablePackageUrls')]
    public function anAdvisoryWithoutAReadablePackageUrlIsRefused(mixed $packageUrl): void
    {
        $codec = new CachedAnswerCodec();
        $entry = $codec->encode([AdvisoryBuilder::build()]);
        $advisory = $entry[0];
        unset($advisory['packageUrl']);
        if ($packageUrl !== null) {
            $advisory['packageUrl'] = $packageUrl;
        }
        $entry[0] = $advisory;

        $this->expectException(UnreadableCacheEntry::class);

        $codec->decode($entry);
    }
}
