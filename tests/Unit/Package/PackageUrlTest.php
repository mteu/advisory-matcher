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

use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

#[CoversClass(PackageUrl::class)]
final class PackageUrlTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function spellingsAndTheirCanonicalForm(): iterable
    {
        yield 'a Composer package' => ['pkg:composer/symfony/http-kernel', 'pkg:composer/symfony/http-kernel'];
        yield 'a Composer package in mixed case' => ['pkg:composer/Symfony/HTTP-Kernel', 'pkg:composer/symfony/http-kernel'];
        yield 'an uppercase type' => ['pkg:COMPOSER/symfony/http-kernel', 'pkg:composer/symfony/http-kernel'];
        yield 'with a version' => ['pkg:composer/symfony/http-kernel@5.4.19', 'pkg:composer/symfony/http-kernel'];
        yield 'with qualifiers and a subpath' => ['pkg:npm/lodash@4.17.20?repository_url=https://example.invalid#lib', 'pkg:npm/lodash'];
        yield 'an npm package' => ['pkg:npm/lodash', 'pkg:npm/lodash'];
        yield 'an npm package published in mixed case' => ['pkg:npm/JSONStream@1.3.5', 'pkg:npm/JSONStream'];
        yield 'a scoped npm package' => ['pkg:npm/@acme/widgets@2.1.0', 'pkg:npm/%40acme/widgets'];
        yield 'a scoped npm package with an encoded scope' => ['pkg:npm/%40acme/widgets', 'pkg:npm/%40acme/widgets'];
        yield 'an npm name with a trailing slash' => ['pkg:npm/JSONStream@1.3.5/', 'pkg:npm/JSONStream'];
        yield 'an encoded letter in an npm name' => ['pkg:npm/JSON%53tream', 'pkg:npm/JSONStream'];
        yield 'an npm name in mixed case behind slashes in qualifiers and subpath' => [
            'pkg:npm/JSONStream@1.3.5?vcs_url=git%2Bhttps://host.invalid/a/b#lib/src',
            'pkg:npm/JSONStream',
        ];
        yield 'the PHP runtime' => ['pkg:generic/php@8.3.6', 'pkg:generic/php'];
        yield 'a colon left unencoded, as packageurl-php writes it' => ['pkg:generic/a:b', 'pkg:generic/a:b'];
        yield 'a type that lowercases its names' => ['pkg:pypi/Django', 'pkg:pypi/django'];
        yield 'a type that keeps the case' => ['pkg:maven/org.Example/Library', 'pkg:maven/org.Example/Library'];
    }

    #[Test]
    #[DataProvider('spellingsAndTheirCanonicalForm')]
    public function writesOneCanonicalFormPerPackage(string $purl, string $canonical): void
    {
        self::assertSame($canonical, PackageUrl::fromString($purl)->toString());
    }

    #[Test]
    #[DataProvider('spellingsAndTheirCanonicalForm')]
    public function readsItsCanonicalFormBackUnchanged(string $purl, string $canonical): void
    {
        self::assertSame($canonical, PackageUrl::fromString(PackageUrl::fromString($purl)->toString())->toString());
    }

    #[Test]
    public function readsTheParts(): void
    {
        $purl = PackageUrl::fromString('pkg:npm/%40acme/widgets@2.1.0');

        self::assertSame('npm', $purl->type);
        self::assertSame('@acme', $purl->namespace);
        self::assertSame('widgets', $purl->name);
    }

    #[Test]
    public function readsAPackageWithoutNamespace(): void
    {
        self::assertSame('', PackageUrl::fromString('pkg:npm/lodash')->namespace);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function registryNames(): iterable
    {
        yield 'a Composer package' => ['composer', 'symfony/console', 'pkg:composer/symfony/console'];
        yield 'a Composer package in mixed case' => ['composer', 'Symfony/Console', 'pkg:composer/symfony/console'];
        yield 'an npm package' => ['npm', 'lodash', 'pkg:npm/lodash'];
        yield 'an npm package published in mixed case' => ['npm', 'JSONStream', 'pkg:npm/JSONStream'];
        yield 'a scoped npm package' => ['npm', '@babel/core', 'pkg:npm/%40babel/core'];
        yield 'the PHP runtime' => ['generic', 'php', 'pkg:generic/php'];
    }

    #[Test]
    #[DataProvider('registryNames')]
    public function buildsThePackageUrlOfARegistryName(string $type, string $packageName, string $canonical): void
    {
        self::assertSame($canonical, PackageUrl::fromPackageName($type, $packageName)->toString());
    }

    #[Test]
    #[DataProvider('registryNames')]
    public function spellsTheRegistryNameBack(string $type, string $packageName, string $canonical): void
    {
        $expected = $type === 'composer' ? strtolower($packageName) : $packageName;

        self::assertSame($expected, PackageUrl::fromString($canonical)->packageName());
    }

    /**
     * @return iterable<string, array{string, Ecosystem}>
     */
    public static function packagesAndTheirEcosystem(): iterable
    {
        yield 'a Composer package' => ['pkg:composer/symfony/console', Ecosystem::Composer];
        yield 'an npm package' => ['pkg:npm/lodash', Ecosystem::Npm];
        yield 'the PHP runtime' => ['pkg:generic/php', Ecosystem::Php];
        yield 'another generic package' => ['pkg:generic/openssl', Ecosystem::Unknown];
        yield 'a generic package named php in a namespace' => ['pkg:generic/acme/php', Ecosystem::Unknown];
        yield 'the runtime under a type the specification does not register' => ['pkg:php/php', Ecosystem::Unknown];
        yield 'a Composer package named php' => ['pkg:composer/php/php', Ecosystem::Composer];
        yield 'a type no source covers' => ['pkg:pypi/django', Ecosystem::Unknown];
        yield 'a distribution package' => ['pkg:deb/debian/openssl', Ecosystem::Unknown];
    }

    #[Test]
    #[DataProvider('packagesAndTheirEcosystem')]
    public function namesTheEcosystemItBelongsTo(string $purl, Ecosystem $expected): void
    {
        self::assertSame($expected, PackageUrl::fromString($purl)->ecosystem());
    }

    #[Test]
    public function treatsTwoSpellingsOfOnePackageAsEqual(): void
    {
        self::assertTrue(PackageUrl::fromString('pkg:npm/@acme/widgets@1.0.0')->equals(PackageUrl::fromString('pkg:NPM/%40acme/widgets')));
    }

    #[Test]
    public function tellsAnNpmPackageFromOneDifferingInCaseOnly(): void
    {
        self::assertFalse(PackageUrl::fromString('pkg:npm/JSONStream')->equals(PackageUrl::fromString('pkg:npm/jsonstream')));
    }

    #[Test]
    #[TestWith([''])]
    #[TestWith(['vendor/package'])]
    #[TestWith(['pkg:composer'])]
    #[TestWith(['pkg:npm/@acme/widgets'])]
    #[TestWith(['https://example.invalid/vendor/package'])]
    public function rejectsAnythingButAPackageUrl(string $purl): void
    {
        $this->expectException(\InvalidArgumentException::class);

        PackageUrl::fromString($purl);
    }

    #[Test]
    #[TestWith(['composer', ''])]
    #[TestWith(['composer', '   '])]
    #[TestWith(['composer', 'vendor/'])]
    #[TestWith(['', 'vendor/package'])]
    public function rejectsARegistryNameWithoutAName(string $type, string $packageName): void
    {
        $this->expectException(\InvalidArgumentException::class);

        PackageUrl::fromPackageName($type, $packageName);
    }

    #[Test]
    public function doesNotEchoTheRejectedInput(): void
    {
        try {
            PackageUrl::fromString('<script>alert(1)</script>');
            self::fail('A malformed package URL was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringNotContainsString('<script>', $exception->getMessage());
        }
    }
}
