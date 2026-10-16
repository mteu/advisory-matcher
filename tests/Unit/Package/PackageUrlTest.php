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

use mteu\AdvisoryMatcher\Package\PackageUrl;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

#[CoversClass(PackageUrl::class)]
final class PackageUrlTest extends TestCase
{
    #[Test]
    #[DataProvider('canonicalSpellingProvider')]
    public function parsesAnySpellingIntoTheCanonicalVersionlessForm(string $purl, string $expected): void
    {
        self::assertSame($expected, PackageUrl::fromString($purl)->toString());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function canonicalSpellingProvider(): iterable
    {
        yield 'Composer package' => ['pkg:composer/symfony/console', 'pkg:composer/symfony/console'];
        // packageurl-php keeps the case here; the specification lowercases.
        yield 'mixed-case Composer package' => ['pkg:composer/Symfony/Console', 'pkg:composer/symfony/console'];
        yield 'npm package' => ['pkg:npm/lodash', 'pkg:npm/lodash'];
        // packageurl-php lowercases here; the specification keeps the case.
        yield 'mixed-case legacy npm package' => ['pkg:npm/JSONStream@1.3.5', 'pkg:npm/JSONStream'];
        yield 'scoped npm package, encoded' => ['pkg:npm/%40babel/core@7.24.0', 'pkg:npm/%40babel/core'];
        yield 'scoped npm package, unencoded' => ['pkg:npm/@babel/core@7.24.0', 'pkg:npm/%40babel/core'];
        yield 'PHP runtime' => ['pkg:generic/php@8.3.6', 'pkg:generic/php'];
        yield 'uppercase scheme and type' => ['PKG:NPM/lodash', 'pkg:npm/lodash'];
        yield 'version, qualifiers and subpath' => [
            'pkg:composer/symfony/console@v7.1.0?repository_url=https://repo.packagist.org#src',
            'pkg:composer/symfony/console',
        ];
        yield 'type no source covers keeps the library rules' => ['pkg:pypi/Django_Rest', 'pkg:pypi/django-rest'];
    }

    #[Test]
    #[DataProvider('packageNameProvider')]
    public function buildsTheSameCanonicalFormFromARegistryName(string $type, string $packageName, string $expected): void
    {
        self::assertSame($expected, PackageUrl::fromPackageName($type, $packageName)->toString());
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function packageNameProvider(): iterable
    {
        yield 'Composer package' => ['composer', 'symfony/console', 'pkg:composer/symfony/console'];
        yield 'mixed-case Composer package' => ['composer', 'Symfony/Console', 'pkg:composer/symfony/console'];
        yield 'npm package' => ['npm', 'lodash', 'pkg:npm/lodash'];
        yield 'mixed-case legacy npm package' => ['npm', 'JSONStream', 'pkg:npm/JSONStream'];
        yield 'scoped npm package' => ['npm', '@babel/core', 'pkg:npm/%40babel/core'];
        yield 'PHP runtime' => ['generic', 'php', 'pkg:generic/php'];
        yield 'uppercase type' => ['NPM', 'lodash', 'pkg:npm/lodash'];
    }

    #[Test]
    #[TestWith(['pkg:npm/%40babel/core', 'npm', '@babel/core'])]
    #[TestWith(['pkg:npm/@babel/core@7.24.0', 'npm', '@babel/core'])]
    #[TestWith(['pkg:composer/Symfony/Console@v7.1.0', 'composer', 'symfony/console'])]
    #[TestWith(['pkg:npm/JSONStream', 'npm', 'JSONStream'])]
    public function aPurlAndItsRegistryNameNameTheSamePackage(string $purl, string $type, string $packageName): void
    {
        self::assertTrue(PackageUrl::fromString($purl)->equals(PackageUrl::fromPackageName($type, $packageName)));
    }

    #[Test]
    public function caseStillTellsNpmPackagesApart(): void
    {
        self::assertFalse(PackageUrl::fromString('pkg:npm/JSONStream')->equals(PackageUrl::fromString('pkg:npm/jsonstream')));
    }

    #[Test]
    #[TestWith(['pkg:composer/symfony/console'])]
    #[TestWith(['pkg:npm/JSONStream'])]
    #[TestWith(['pkg:npm/%40babel/core'])]
    #[TestWith(['pkg:generic/php'])]
    #[TestWith(['pkg:golang/github.com/gorilla/mux'])]
    #[TestWith(['pkg:npm/a:b'])]
    public function theCanonicalFormParsesBackToItself(string $canonical): void
    {
        self::assertSame($canonical, PackageUrl::fromString($canonical)->toString());
    }

    #[Test]
    #[TestWith(['pkg:composer/symfony/console', 'symfony/console'])]
    #[TestWith(['pkg:npm/%40babel/core', '@babel/core'])]
    #[TestWith(['pkg:npm/JSONStream', 'JSONStream'])]
    #[TestWith(['pkg:generic/php', 'php'])]
    public function joinsNamespaceAndNameAsTheRegistrySpellsThem(string $purl, string $expected): void
    {
        self::assertSame($expected, PackageUrl::fromString($purl)->packageName());
    }

    #[Test]
    #[TestWith([''])]
    #[TestWith(['symfony/console'])]
    #[TestWith(['https://example.org/pkg/npm/lodash'])]
    #[TestWith(['pkg:npm/'])]
    #[TestWith(['pkg:np m/lodash'])]
    #[TestWith(['pkg:1npm/lodash'])]
    #[TestWith(['pkg:npm/foo%2Fbar'])]
    #[TestWith(['pkg:packagist/symfony/console'])]
    #[TestWith(['pkg:node/lodash'])]
    #[TestWith(['pkg:php/php@8.3.6'])]
    public function rejectsWhatIsNotARegisteredPackageUrl(string $purl): void
    {
        $this->expectException(\InvalidArgumentException::class);

        PackageUrl::fromString($purl);
    }

    #[Test]
    #[TestWith(['composer', ''])]
    #[TestWith(['composer', 'symfony/'])]
    #[TestWith(['npm', '/lodash'])]
    #[TestWith(['npm', '@babel//core'])]
    #[TestWith(['', 'lodash'])]
    #[TestWith(['php', 'php'])]
    #[TestWith(['packagist', 'symfony/console'])]
    public function rejectsWhatIsNotARegisteredPackageName(string $type, string $packageName): void
    {
        $this->expectException(\InvalidArgumentException::class);

        PackageUrl::fromPackageName($type, $packageName);
    }

    #[Test]
    public function doesNotEchoTheRejectedInput(): void
    {
        $input = 'pkg:<script>alert(1)</script>/x';

        try {
            PackageUrl::fromString($input);
            self::fail('The input should have been rejected.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringNotContainsString('<script>', $exception->getMessage());
        }
    }
}
