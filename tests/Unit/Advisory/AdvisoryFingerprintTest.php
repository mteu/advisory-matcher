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
use mteu\AdvisoryMatcher\Advisory\AdvisoryFingerprint;
use mteu\AdvisoryMatcher\Advisory\AdvisoryReference;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProviderExternal;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

#[CoversClass(AdvisoryFingerprint::class)]
final class AdvisoryFingerprintTest extends TestCase
{
    #[Test]
    public function prefersTheCveOverEveryOtherIdentity(): void
    {
        $advisory = AdvisoryBuilder::build(
            advisoryId: 'PKSA-1111-2222-3333',
            remoteId: 'GHSA-aaaa-bbbb-cccc',
            cve: 'CVE-2026-1234',
        );

        self::assertSame('composer|vendor/package|cve|CVE-2026-1234', AdvisoryFingerprint::canonical($advisory));
    }

    #[Test]
    public function oneNameInTwoEcosystemsSharesNoIdentity(): void
    {
        $npm = AdvisoryBuilder::build(
            advisoryId: 'OSV-GHSA-aaaa-bbbb-cccc',
            packageName: 'debug',
            ecosystem: Ecosystem::Npm,
            cve: 'CVE-2026-1234',
        );
        $pypi = AdvisoryBuilder::build(
            advisoryId: 'OSV-GHSA-aaaa-bbbb-cccc',
            packageName: 'debug',
            ecosystem: Ecosystem::Composer,
            cve: 'CVE-2026-1234',
        );

        self::assertSame('npm|debug|cve|CVE-2026-1234', AdvisoryFingerprint::canonical($npm));
        self::assertSame(
            [],
            array_intersect(AdvisoryFingerprint::identitiesOf($npm), AdvisoryFingerprint::identitiesOf($pypi)),
        );
    }

    #[Test]
    public function fallsBackToTheGithubAdvisoryIdWhenNoCveIsKnown(): void
    {
        $advisory = AdvisoryBuilder::build(advisoryId: 'PKSA-1111-2222-3333', remoteId: 'GHSA-aaaa-bbbb-cccc');

        self::assertSame('composer|vendor/package|ghsa|GHSA-AAAA-BBBB-CCCC', AdvisoryFingerprint::canonical($advisory));
    }

    #[Test]
    public function fallsBackToTheNativeIdWhenNothingMorePortableIsKnown(): void
    {
        $advisory = AdvisoryBuilder::build(advisoryId: 'PKSA-1111-2222-3333');

        self::assertSame('composer|vendor/package|id|PKSA-1111-2222-3333', AdvisoryFingerprint::canonical($advisory));
    }

    #[Test]
    public function derivesAStableKeyFromContentWhenNothingNamesTheAdvisory(): void
    {
        $advisory = AdvisoryBuilder::build(advisoryId: '', title: 'A vulnerability', affectedVersions: '<1.6.0');

        $fingerprint = AdvisoryFingerprint::canonical($advisory);

        self::assertStringStartsWith('composer|vendor/package|hash|', $fingerprint);
        self::assertSame($fingerprint, AdvisoryFingerprint::canonical($advisory));
    }

    #[Test]
    public function distinguishesUnnamedAdvisoriesOfTheSamePackage(): void
    {
        $first = AdvisoryBuilder::build(advisoryId: '', title: 'First problem');
        $second = AdvisoryBuilder::build(advisoryId: '', title: 'Second problem');

        self::assertNotSame(AdvisoryFingerprint::canonical($first), AdvisoryFingerprint::canonical($second));
    }

    #[Test]
    #[TestWith(['cve-2026-1234'])]
    #[TestWith(['  CVE-2026-1234  '])]
    #[TestWith(['Cve-2026-1234'])]
    public function normalisesCveSpellingSoTheKeyDoesNotShift(string $cve): void
    {
        $advisory = AdvisoryBuilder::build(cve: $cve);

        self::assertSame('composer|vendor/package|cve|CVE-2026-1234', AdvisoryFingerprint::canonical($advisory));
    }

    #[Test]
    public function scopesEveryIdentityToItsPackage(): void
    {
        $first = AdvisoryBuilder::build(packageName: 'vendor/first', cve: 'CVE-2026-1234');
        $second = AdvisoryBuilder::build(packageName: 'vendor/second', cve: 'CVE-2026-1234');

        self::assertNotSame(AdvisoryFingerprint::canonical($first), AdvisoryFingerprint::canonical($second));
    }

    #[Test]
    public function listsEveryIdentityMostPortableFirst(): void
    {
        $advisory = AdvisoryBuilder::build(
            advisoryId: 'PKSA-1111-2222-3333',
            remoteId: 'GHSA-aaaa-bbbb-cccc',
            cve: 'CVE-2026-1234',
        );

        self::assertSame(
            [
                'composer|vendor/package|cve|CVE-2026-1234',
                'composer|vendor/package|ghsa|GHSA-AAAA-BBBB-CCCC',
                'composer|vendor/package|id|PKSA-1111-2222-3333',
            ],
            AdvisoryFingerprint::identitiesOf($advisory),
        );
    }

    #[Test]
    public function findsAGithubAdvisoryIdBehindItsOsvPrefix(): void
    {
        $advisory = AdvisoryBuilder::build(advisoryId: 'OSV-GHSA-aaaa-bbbb-cccc');

        self::assertContains('composer|vendor/package|ghsa|GHSA-AAAA-BBBB-CCCC', AdvisoryFingerprint::identitiesOf($advisory));
    }

    #[Test]
    public function findsAGithubAdvisoryIdAmongTheReferences(): void
    {
        $advisory = AdvisoryBuilder::build(
            advisoryId: 'PKSA-1111-2222-3333',
            references: [new AdvisoryReference('github', 'GHSA-aaaa-bbbb-cccc')],
        );

        self::assertContains('composer|vendor/package|ghsa|GHSA-AAAA-BBBB-CCCC', AdvisoryFingerprint::identitiesOf($advisory));
    }

    #[Test]
    public function listsOneGithubAdvisoryIdWhenSeveralPlacesCarryIt(): void
    {
        $advisory = AdvisoryBuilder::build(
            advisoryId: 'OSV-GHSA-aaaa-bbbb-cccc',
            remoteId: 'GHSA-aaaa-bbbb-cccc',
            references: [
                new AdvisoryReference('github', 'GHSA-aaaa-bbbb-cccc'),
                new AdvisoryReference('osv', 'OSV-GHSA-aaaa-bbbb-cccc'),
            ],
        );

        $ghsaIdentities = array_filter(
            AdvisoryFingerprint::identitiesOf($advisory),
            static fn (string $identity): bool => str_contains($identity, '|ghsa|'),
        );

        self::assertCount(1, $ghsaIdentities);
    }

    #[Test]
    public function ignoresIdentifiersThatAreNotGithubAdvisoryIds(): void
    {
        $advisory = AdvisoryBuilder::build(
            advisoryId: 'PKSA-1111-2222-3333',
            references: [new AdvisoryReference('friendsofphp', 'vendor/package/2026-01-01.yaml')],
        );

        foreach (AdvisoryFingerprint::identitiesOf($advisory) as $identity) {
            self::assertStringNotContainsString('|ghsa|', $identity);
        }
    }

    #[Test]
    #[DataProviderExternal(AdvisoryFingerprintStoredFormatTest::class, 'packagesAndTheKeyTheyAreStoredUnder')]
    public function namesAStatementAboutTheAdvisoryByTheIdentitiesTheAdvisoryAnswersTo(string $purl, string $packageKey): void
    {
        $package = PackageUrl::fromString($purl);
        $naming = AdvisoryFingerprint::identitiesNaming($package, ['CVE-2026-1234', 'GHSA-aaaa-bbbb-cccc', 'PKSA-1111-2222-3333']);

        self::assertStringStartsWith($packageKey . '|', $naming[0]);
        self::assertEqualsCanonicalizing(
            AdvisoryFingerprint::identitiesOf(AdvisoryBuilder::onPackage($package)),
            $naming,
        );
    }

    #[Test]
    public function namesACveAndAGithubAdvisoryIdInUpperCaseAndAFeedsOwnIdAsWritten(): void
    {
        self::assertSame(
            [
                'composer|vendor/package|cve|CVE-2026-1234',
                'composer|vendor/package|ghsa|GHSA-AAAA-BBBB-CCCC',
                'composer|vendor/package|id|pksa-1111',
            ],
            AdvisoryFingerprint::identitiesNaming(PackageUrl::fromString('pkg:composer/vendor/package'), [' cve-2026-1234 ', 'ghsa-aaaa-bbbb-cccc', 'pksa-1111']),
        );
    }

    #[Test]
    public function skipsAnIdThatIsBlankOrWouldNameAnotherIdentity(): void
    {
        self::assertSame(
            ['npm|lodash|cve|CVE-2026-1234'],
            AdvisoryFingerprint::identitiesNaming(PackageUrl::fromString('pkg:npm/lodash'), ['', '   ', 'id|CVE-2026-9999', 'CVE-2026-1234']),
        );
    }

    #[Test]
    public function namesEachIdentityOnceWhateverTheSpelling(): void
    {
        self::assertSame(
            ['npm|lodash|cve|CVE-2026-1234'],
            AdvisoryFingerprint::identitiesNaming(PackageUrl::fromString('pkg:npm/lodash'), ['CVE-2026-1234', 'cve-2026-1234']),
        );
    }
}
