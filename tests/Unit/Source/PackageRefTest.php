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

namespace mteu\AdvisoryMatcher\Tests\Unit\Source;

use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Source\PackageRef;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(PackageRef::class)]
final class PackageRefTest extends TestCase
{
    #[Test]
    public function readsTheEcosystemAndTheRegistryNameFromThePackageUrl(): void
    {
        $reference = new PackageRef(PackageUrl::fromString('pkg:npm/%40acme/widgets'), '2.1.0');

        self::assertSame(Ecosystem::Npm, $reference->ecosystem);
        self::assertSame('@acme/widgets', $reference->name);
    }

    #[Test]
    #[DataProvider('acceptedVersionProvider')]
    public function acceptsAnyVersionTheRealWorldProduces(string $version): void
    {
        self::assertSame($version, (new PackageRef(PackageUrl::fromPackageName('composer', 'vendor/one'), $version))->version);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function acceptedVersionProvider(): iterable
    {
        yield 'distribution patched runtime' => ['8.3.14-1~deb12u1'];
        yield 'placeholder' => ['unknown'];
        yield 'absent' => [''];
        yield 'branch' => ['dev-main'];
    }

    #[Test]
    public function twoReferencesToTheSameQuestionAreEqual(): void
    {
        $one = new PackageRef(PackageUrl::fromPackageName('composer', 'vendor/one'), '1.0.0');
        $other = new PackageRef(PackageUrl::fromString('pkg:composer/Vendor/One'), '1.0.0');

        self::assertTrue($one->equals($other));
        self::assertSame($one->identity(), $other->identity());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function differingReferenceProvider(): iterable
    {
        yield 'another ecosystem' => ['pkg:npm/vendor/one', '1.0.0'];
        yield 'another name' => ['pkg:composer/vendor/two', '1.0.0'];
        yield 'another version' => ['pkg:composer/vendor/one', '1.0.1'];
    }

    #[Test]
    #[DataProvider('differingReferenceProvider')]
    public function referencesDifferingInAnyFieldAreNotEqual(string $purl, string $version): void
    {
        $reference = new PackageRef(PackageUrl::fromString('pkg:composer/vendor/one'), '1.0.0');
        $other = new PackageRef(PackageUrl::fromString($purl), $version);

        self::assertFalse($reference->equals($other));
        self::assertNotSame($reference->identity(), $other->identity());
    }

    #[Test]
    public function twoPackagesOfOneNameOutsideEveryEcosystemAreNotEqual(): void
    {
        $python = new PackageRef(PackageUrl::fromString('pkg:pypi/requests'), '2.31.0');
        $ruby = new PackageRef(PackageUrl::fromString('pkg:gem/requests'), '2.31.0');

        self::assertFalse($python->equals($ruby));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function packageUrlsWithAVersion(): iterable
    {
        yield 'a Composer package' => ['pkg:composer/symfony/http-kernel@5.4.19', '5.4.19', 'pkg:composer/symfony/http-kernel@5.4.19'];
        yield 'a Composer package in mixed case' => ['pkg:composer/Symfony/HTTP-Kernel@5.4.19', '5.4.19', 'pkg:composer/symfony/http-kernel@5.4.19'];
        yield 'an npm package published in mixed case' => ['pkg:npm/JSONStream@1.3.5', '1.3.5', 'pkg:npm/JSONStream@1.3.5'];
        yield 'a scoped npm package' => ['pkg:npm/@acme/widgets@2.1.0', '2.1.0', 'pkg:npm/%40acme/widgets@2.1.0'];
        yield 'with qualifiers and a subpath' => ['pkg:npm/lodash@4.17.20?repository_url=https://example.invalid#lib', '4.17.20', 'pkg:npm/lodash@4.17.20'];
        yield 'a version with build metadata' => ['pkg:generic/php@8.3.14%2Bdeb12u1', '8.3.14+deb12u1', 'pkg:generic/php@8.3.14%2Bdeb12u1'];
        yield 'no version' => ['pkg:composer/vendor/one', '', 'pkg:composer/vendor/one'];
    }

    #[Test]
    #[DataProvider('packageUrlsWithAVersion')]
    public function readsThePackageAndTheVersionFromAPackageUrl(string $purl, string $version, string $canonical): void
    {
        $reference = PackageRef::fromString($purl);

        self::assertSame($version, $reference->version);
        self::assertSame($canonical, $reference->toString());
    }

    #[Test]
    #[DataProvider('packageUrlsWithAVersion')]
    public function readsItsCanonicalFormBackUnchanged(string $purl, string $version, string $canonical): void
    {
        self::assertTrue(PackageRef::fromString($canonical)->equals(PackageRef::fromString($purl)));
        self::assertSame($canonical, PackageRef::fromString($canonical)->toString());
    }

    #[Test]
    public function rejectsSomethingThatIsNoPackageUrl(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        PackageRef::fromString('vendor/one@1.0.0');
    }
}
