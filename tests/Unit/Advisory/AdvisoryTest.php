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
use mteu\AdvisoryMatcher\Advisory\AdvisoryReference;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Version\AffectedVersions;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Advisory::class)]
final class AdvisoryTest extends TestCase
{
    #[Test]
    #[DataProvider('unsafeLinks')]
    public function refusesALinkThatIsNotHttp(string $link): void
    {
        $this->expectException(\InvalidArgumentException::class);

        AdvisoryBuilder::build(link: $link);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unsafeLinks(): iterable
    {
        yield 'javascript uri' => ['javascript:alert(1)'];
        yield 'javascript uri in upper case' => ['JAVASCRIPT:alert(1)'];
        yield 'data uri' => ['data:text/html,<script>alert(1)</script>'];
        yield 'no scheme at all' => ['www.example.invalid/advisory'];
        yield 'leading whitespace hiding the scheme' => [' javascript:alert(1)'];
        yield 'blank' => ['   '];
    }

    #[Test]
    #[DataProvider('safeLinks')]
    public function acceptsAnHttpLinkOrNone(string $link): void
    {
        self::assertSame($link, AdvisoryBuilder::build(link: $link)->link);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function safeLinks(): iterable
    {
        yield 'https' => ['https://example.invalid/advisory'];
        yield 'http' => ['http://example.invalid/advisory'];
        yield 'scheme in upper case' => ['HTTPS://example.invalid/advisory'];
        yield 'no link' => [''];
    }

    #[Test]
    #[DataProvider('blankNames')]
    public function refusesAnAdvisoryFiledUnderNoPackage(string $packageName): void
    {
        $this->expectException(\InvalidArgumentException::class);

        AdvisoryBuilder::build(packageName: $packageName);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function blankNames(): iterable
    {
        yield 'empty' => [''];
        yield 'whitespace' => ["  \t"];
    }

    #[Test]
    public function refusesReferencesThatAreNotAList(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        self::buildAdvisoryPastTheTypeChecker(['GitHub' => new AdvisoryReference('GitHub', 'GHSA-aaaa-bbbb-cccc')]);
    }

    #[Test]
    public function refusesAReferenceThatIsNotAnAdvisoryReference(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        self::buildAdvisoryPastTheTypeChecker(['GHSA-aaaa-bbbb-cccc']);
    }

    #[Test]
    public function reportsRemediationOnlyWhenAVersionIsNamed(): void
    {
        self::assertFalse(AdvisoryBuilder::build()->hasRemediation());
        self::assertTrue(AdvisoryBuilder::build(firstPatchedVersion: '1.6.0')->hasRemediation());
    }

    #[Test]
    public function reportsACveOnlyWhenOneIsNamed(): void
    {
        self::assertFalse(AdvisoryBuilder::build(cve: '')->hasCve());
        self::assertTrue(AdvisoryBuilder::build(cve: 'CVE-2026-1234')->hasCve());
    }

    #[Test]
    public function exposesTheFingerprintItIsPersistedUnder(): void
    {
        $advisory = AdvisoryBuilder::build(packageName: 'vendor/package', cve: 'CVE-2026-1234');

        self::assertSame('composer|vendor/package|cve|CVE-2026-1234', $advisory->getFingerprint());
    }

    /**
     * @param array<mixed> $references
     */
    private static function buildAdvisoryPastTheTypeChecker(array $references): Advisory
    {
        return (new \ReflectionClass(Advisory::class))->newInstanceArgs([
            'advisoryId' => 'PKSA-1111-2222-3333',
            'packageName' => 'vendor/package',
            'ecosystem' => Ecosystem::Composer,
            'title' => 'A vulnerability',
            'link' => 'https://example.invalid/advisory',
            'cve' => '',
            'affectedVersions' => AffectedVersions::fromComposerConstraint('>=1.0.0,<1.6.0'),
            'reportedAt' => new \DateTimeImmutable('2026-01-01T00:00:00+00:00'),
            'severity' => Severity::Medium,
            'references' => $references,
        ]);
    }
}
