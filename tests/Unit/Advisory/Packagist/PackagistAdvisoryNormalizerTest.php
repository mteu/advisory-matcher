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

namespace mteu\AdvisoryMatcher\Tests\Unit\Advisory\Packagist;

use mteu\AdvisoryMatcher\Advisory\AdvisoryReference;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Advisory\Packagist\PackagistAdvisoryNormalizer;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Tests\Unit\Clock\FrozenClock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(PackagistAdvisoryNormalizer::class)]
final class PackagistAdvisoryNormalizerTest extends TestCase
{
    private const string FROZEN_NOW = '2026-09-24T12:00:00+00:00';

    private PackagistAdvisoryNormalizer $normalizer;

    protected function setUp(): void
    {
        $this->normalizer = new PackagistAdvisoryNormalizer(FrozenClock::at(self::FROZEN_NOW));
    }

    #[Test]
    public function mapsARecordAsPackagistSendsItOntoAnAdvisory(): void
    {
        $advisory = $this->normalizer->normalize(
            [
                'advisoryId' => 'PKSA-dmw8-jd8k-q3c6',
                'packageName' => 'monolog/monolog',
                'remoteId' => 'monolog/monolog/2014-12-29-1.yaml',
                'title' => 'Header injection in NativeMailerHandler',
                'link' => 'https://github.com/Seldaek/monolog/pull/448#issuecomment-68208704',
                'cve' => null,
                'affectedVersions' => '>=1.8.0,<1.12.0',
                'source' => 'FriendsOfPHP/security-advisories',
                'reportedAt' => '2014-12-29 00:00:00',
                'composerRepository' => 'https://packagist.org',
                'severity' => 'low',
                'sources' => [
                    ['name' => 'GitHub', 'remoteId' => 'GHSA-f57v-q966-7fh6'],
                    ['name' => 'FriendsOfPHP/security-advisories', 'remoteId' => 'monolog/monolog/2014-12-29-1.yaml'],
                ],
            ],
            PackageUrl::fromPackageName('composer', 'monolog/monolog'),
        );

        self::assertSame('PKSA-dmw8-jd8k-q3c6', $advisory->advisoryId);
        self::assertSame('monolog/monolog', $advisory->packageName);
        self::assertSame(Ecosystem::Composer, $advisory->ecosystem);
        self::assertSame('Header injection in NativeMailerHandler', $advisory->title);
        self::assertSame('https://github.com/Seldaek/monolog/pull/448#issuecomment-68208704', $advisory->link);
        self::assertSame('', $advisory->cve);
        self::assertSame('>=1.8.0,<1.12.0', $advisory->affectedVersions->toComposerConstraint());
        self::assertSame('2014-12-29T00:00:00+00:00', $advisory->reportedAt->format(\DateTimeInterface::ATOM));
        self::assertSame(Severity::Low, $advisory->severity);
        self::assertEquals(
            [
                new AdvisoryReference('GitHub', 'GHSA-f57v-q966-7fh6'),
                new AdvisoryReference('FriendsOfPHP/security-advisories', 'monolog/monolog/2014-12-29-1.yaml'),
            ],
            $advisory->references,
        );
        self::assertSame('1.12.0', $advisory->firstPatchedVersion);
    }

    #[Test]
    public function filesTheAdvisoryUnderTheLowercasedComposerName(): void
    {
        $advisory = $this->normalizer->normalize(
            ['advisoryId' => 'PKSA-1', 'packageName' => 'phpmailer/phpmailer'],
            PackageUrl::fromPackageName('composer', 'PHPMailer/PHPMailer'),
        );

        self::assertSame('phpmailer/phpmailer', $advisory->packageName);
    }

    /**
     * @return \Generator<string, array{string}>
     */
    public static function linksThatMustNotBecomeALinkTarget(): \Generator
    {
        yield 'javascript' => ['javascript:alert(document.cookie)'];
        yield 'javascript, mixed case and padded' => ['  JaVaScRiPt:alert(1)'];
        yield 'data' => ['data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='];
        yield 'relative' => ['/advisories/PKSA-1'];
        yield 'vbscript' => ['vbscript:msgbox(1)'];
        yield 'file' => ['file:///etc/passwd'];
        yield 'schemeless' => ['//evil.example.com'];
    }

    #[Test]
    public function keepsAPlainHttpLink(): void
    {
        $advisory = $this->normalizer->normalize(
            ['advisoryId' => 'PKSA-1', 'link' => 'http://example.com/advisory'],
            PackageUrl::fromPackageName('composer', 'vendor/package'),
        );

        self::assertSame('http://example.com/advisory', $advisory->link);
    }

    #[Test]
    #[DataProvider('linksThatMustNotBecomeALinkTarget')]
    public function dropsALinkThatIsNotHttp(string $link): void
    {
        $advisory = $this->normalizer->normalize(['advisoryId' => 'PKSA-1', 'link' => $link], PackageUrl::fromPackageName('composer', 'vendor/package'));

        self::assertSame('', $advisory->link);
    }

    #[Test]
    public function aRecordMissingEverythingStillBecomesAnAdvisory(): void
    {
        $advisory = $this->normalizer->normalize(['advisoryId' => 'PKSA-1'], PackageUrl::fromPackageName('composer', 'vendor/package'));

        self::assertSame('', $advisory->title);
        self::assertSame('', $advisory->affectedVersions->toComposerConstraint());
        self::assertSame('', $advisory->firstPatchedVersion);
        self::assertSame([], $advisory->references);
        self::assertSame(Severity::Unknown, $advisory->severity);
        self::assertSame(self::FROZEN_NOW, $advisory->reportedAt->format(\DateTimeInterface::ATOM));
    }

    #[Test]
    public function anUnreadableDateIsDatedToWhenItWasRead(): void
    {
        $advisory = $this->normalizer->normalize(
            ['advisoryId' => 'PKSA-1', 'reportedAt' => 'sometime last spring'],
            PackageUrl::fromPackageName('composer', 'vendor/package'),
        );

        self::assertSame(self::FROZEN_NOW, $advisory->reportedAt->format(\DateTimeInterface::ATOM));
    }

    #[Test]
    public function anIsoDateIsReadAsWell(): void
    {
        $advisory = $this->normalizer->normalize(
            ['advisoryId' => 'PKSA-1', 'reportedAt' => '2024-02-02T20:43:57+00:00'],
            PackageUrl::fromPackageName('composer', 'vendor/package'),
        );

        self::assertSame('2024-02-02T20:43:57+00:00', $advisory->reportedAt->format(\DateTimeInterface::ATOM));
    }

    #[Test]
    public function malformedSourceEntriesAreSkipped(): void
    {
        $advisory = $this->normalizer->normalize(
            [
                'advisoryId' => 'PKSA-1',
                'sources' => [
                    'not a source',
                    ['name' => 'GitHub'],
                    ['name' => 'GitHub', 'remoteId' => 'GHSA-aaaa-bbbb-cccc'],
                ],
            ],
            PackageUrl::fromPackageName('composer', 'vendor/package'),
        );

        self::assertEquals([new AdvisoryReference('GitHub', 'GHSA-aaaa-bbbb-cccc')], $advisory->references);
    }

    #[Test]
    public function keepsTheRecordsOwnSourceAsAReferenceWhenItListsNoSources(): void
    {
        $advisory = $this->normalizer->normalize(
            ['advisoryId' => 'PKSA-1', 'source' => 'GitHub', 'remoteId' => 'GHSA-aaaa-bbbb-cccc'],
            PackageUrl::fromPackageName('composer', 'vendor/package'),
        );

        self::assertEquals([new AdvisoryReference('GitHub', 'GHSA-aaaa-bbbb-cccc')], $advisory->references);
    }

    #[Test]
    public function listsTheRecordsOwnSourceOnceWhenItIsAlsoAmongItsSources(): void
    {
        $advisory = $this->normalizer->normalize(
            [
                'advisoryId' => 'PKSA-1',
                'source' => 'GitHub',
                'remoteId' => 'GHSA-aaaa-bbbb-cccc',
                'sources' => [
                    ['name' => 'GitHub', 'remoteId' => 'GHSA-aaaa-bbbb-cccc'],
                    ['name' => 'FriendsOfPHP/security-advisories', 'remoteId' => 'vendor/package/2026-01-01.yaml'],
                ],
            ],
            PackageUrl::fromPackageName('composer', 'vendor/package'),
        );

        self::assertEquals(
            [
                new AdvisoryReference('GitHub', 'GHSA-aaaa-bbbb-cccc'),
                new AdvisoryReference('FriendsOfPHP/security-advisories', 'vendor/package/2026-01-01.yaml'),
            ],
            $advisory->references,
        );
    }

    #[Test]
    #[DataProvider('constraintsOutsideTheModel')]
    public function aConstraintOutsideTheModelStatesNoAffectedVersions(string $constraint): void
    {
        $advisory = $this->normalizer->normalize(
            ['advisoryId' => 'PKSA-1', 'affectedVersions' => $constraint],
            PackageUrl::fromPackageName('composer', 'vendor/package'),
        );

        self::assertTrue($advisory->affectedVersions->isEmpty());
        self::assertSame('', $advisory->firstPatchedVersion);
    }

    /**
     * @return \Generator<string, array{string}>
     */
    public static function constraintsOutsideTheModel(): \Generator
    {
        yield 'caret' => ['^1.0'];
        yield 'tilde' => ['~1.4'];
        yield 'wildcard' => ['1.2.*'];
        yield 'not equal' => ['!=1.0.0'];
    }

    /**
     * @return \Generator<string, array{string, string}>
     */
    public static function constraintsAndTheirFix(): \Generator
    {
        yield 'single range' => ['>=1.0.0,<1.6.0', '1.6.0'];
        yield 'several branches, nearest fix wins' => ['>=5.0.0,<5.2.27|>=6.0.0,<6.0.6', '5.2.27'];
        yield 'several branches, lower one listed last' => ['>=1.1.0,<1.1.2|>=1.0.0,<1.0.5', '1.0.5'];
        yield 'an inclusive bound after a lower one' => ['>=1.0.0,<=1.2.3', ''];
        yield 'an inclusive bound names no fix' => ['<=1.2.3', ''];
        yield 'v-prefixed' => ['<v2.0.1', '2.0.1'];
        yield 'no upper bound' => ['>=1.0.0', ''];
    }

    #[Test]
    #[DataProvider('constraintsAndTheirFix')]
    public function takesTheLowestFixAcrossRangesAsFirstPatchedVersion(string $constraint, string $expected): void
    {
        $advisory = $this->normalizer->normalize(
            ['advisoryId' => 'PKSA-1', 'affectedVersions' => $constraint],
            PackageUrl::fromPackageName('composer', 'vendor/package'),
        );

        self::assertSame($expected, $advisory->firstPatchedVersion);
    }

    /**
     * @return \Generator<string, array{mixed, Severity}>
     */
    public static function severityLabels(): \Generator
    {
        yield 'critical' => ['critical', Severity::Critical];
        yield 'high' => ['high', Severity::High];
        yield 'medium' => ['medium', Severity::Medium];
        yield 'moderate' => ['moderate', Severity::Medium];
        yield 'null, as FriendsOfPHP records send it' => [null, Severity::Unknown];
        yield 'empty' => ['', Severity::Unknown];
        yield 'a label no scale defines' => ['severe', Severity::Unknown];
    }

    #[Test]
    #[DataProvider('severityLabels')]
    public function readsTheSeverityLabel(mixed $label, Severity $expected): void
    {
        $advisory = $this->normalizer->normalize(['advisoryId' => 'PKSA-1', 'severity' => $label], PackageUrl::fromPackageName('composer', 'vendor/package'));

        self::assertSame($expected, $advisory->severity);
    }
}
