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
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Package\PlatformProduct;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(PlatformProduct::class)]
final class PlatformProductTest extends TestCase
{
    #[Test]
    public function everyProductIsAGenericPackageInThePlatformEcosystem(): void
    {
        foreach (PlatformProduct::cases() as $product) {
            $package = PackageUrl::fromPackageName('generic', $product->value);

            self::assertSame(Ecosystem::Platform, $package->ecosystem(), $product->name);
            self::assertNotSame('', $product->getDisplayName());
        }
    }

    /**
     * @return iterable<string, array{PlatformProduct, string}>
     */
    public static function productsAndTheirCpe(): iterable
    {
        yield 'Apache HTTP Server' => [PlatformProduct::ApacheHttpServer, 'cpe:2.3:a:apache:http_server:'];
        yield 'MariaDB' => [PlatformProduct::MariaDb, 'cpe:2.3:a:mariadb:mariadb:'];
        yield 'PostgreSQL' => [PlatformProduct::PostgreSql, 'cpe:2.3:a:postgresql:postgresql:'];
        yield 'SQLite' => [PlatformProduct::Sqlite, 'cpe:2.3:a:sqlite:sqlite:'];
    }

    #[Test]
    #[DataProvider('productsAndTheirCpe')]
    public function aProductNvdFilesUnderOneCpeResolvesToIt(PlatformProduct $product, string $criteriaPrefix): void
    {
        self::assertSame($criteriaPrefix, $product->cpeIdentity()?->criteriaPrefix());
    }

    #[Test]
    public function aProductNvdFilesUnderSeveralCpesResolvesToNone(): void
    {
        self::assertNotInstanceOf(CpeIdentity::class, PlatformProduct::Nginx->cpeIdentity());
        self::assertNotInstanceOf(CpeIdentity::class, PlatformProduct::MySql->cpeIdentity());
    }
}
