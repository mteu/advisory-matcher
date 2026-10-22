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

namespace mteu\AdvisoryMatcher\Tests\Unit\Package;

use mteu\AdvisoryMatcher\Package\CpeIdentity;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(CpeIdentity::class)]
final class CpeIdentityTest extends TestCase
{
    #[Test]
    public function thePhpRuntimeResolvesToTheInterpretersOfficialCpe(): void
    {
        $identity = CpeIdentity::forPackage(PackageUrl::fromString('pkg:generic/php'));

        self::assertInstanceOf(CpeIdentity::class, $identity);
        self::assertSame('a', $identity->part);
        self::assertSame('php', $identity->vendor);
        self::assertSame('php', $identity->product);
    }

    #[Test]
    public function aPlatformComponentResolvesToItsProductsCpe(): void
    {
        $identity = CpeIdentity::forPackage(PackageUrl::fromString('pkg:generic/httpd'));

        self::assertInstanceOf(CpeIdentity::class, $identity);
        self::assertSame('cpe:2.3:a:apache:http_server:', $identity->criteriaPrefix());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function packagesWithoutAKnownCpe(): iterable
    {
        yield 'a Composer package' => ['pkg:composer/typo3/cms-core'];
        yield 'a Composer package named like the runtime' => ['pkg:composer/php/php'];
        yield 'an npm package named like the runtime' => ['pkg:npm/php'];
        yield 'another runtime' => ['pkg:generic/php-fpm'];
        yield 'another generic package' => ['pkg:generic/openssl'];
        yield 'a platform product NVD files under several CPEs' => ['pkg:generic/nginx'];
        yield 'the runtime under a type the specification does not register' => ['pkg:php/php'];
    }

    #[Test]
    #[DataProvider('packagesWithoutAKnownCpe')]
    public function aPackageNoCpeIsKnownForResolvesToNone(string $purl): void
    {
        self::assertNull(CpeIdentity::forPackage(PackageUrl::fromString($purl)));
    }

    #[Test]
    public function theCpeNameIsWellFormedForNvd(): void
    {
        $name = CpeIdentity::application('php', 'php')->nameForVersion('8.3.14');

        self::assertSame('cpe:2.3:a:php:php:8.3.14:*:*:*:*:*:*:*', $name);
        self::assertCount(13, explode(':', $name));
    }

    #[Test]
    public function theCriteriaPrefixMatchesThisProductsCpeMatchEntries(): void
    {
        self::assertSame('cpe:2.3:a:php:php:', CpeIdentity::application('php', 'php')->criteriaPrefix());
    }

    #[Test]
    #[DataProvider('versionProvider')]
    public function theReleaseIsTheUpstreamVersionOrNothing(string $installed, string $expected): void
    {
        self::assertSame($expected, CpeIdentity::application('php', 'php')->releaseOf($installed));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function versionProvider(): iterable
    {
        yield 'plain version' => ['8.3.14', '8.3.14'];
        yield 'distribution packaging revision' => ['8.3.14-1~deb12u1', '8.3.14'];
        yield 'release candidate' => ['8.5.0RC1', '8.5.0'];
        yield 'build metadata' => ['8.3.14+ubuntu1', '8.3.14'];
        yield 'v prefix' => ['v8.3.14', '8.3.14'];
        yield 'major only' => ['8', '8'];
        yield 'placeholder' => ['unknown', ''];
        yield 'empty' => ['', ''];
        yield 'git hash' => ['a1b2c3d', ''];
    }

    #[Test]
    public function aVersionNamingNoReleaseYieldsNoCpeName(): void
    {
        self::assertSame('', CpeIdentity::application('php', 'php')->nameForVersion('unknown'));
    }

    #[Test]
    public function anIdentityWithoutAProductIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new CpeIdentity('a', 'php', ' ');
    }
}
