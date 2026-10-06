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
use mteu\AdvisoryMatcher\Source\PackageRef;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(PackageRef::class)]
final class PackageRefTest extends TestCase
{
    #[Test]
    #[DataProvider('blankNameProvider')]
    public function rejectsAReferenceWithoutAName(string $name): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new PackageRef(Ecosystem::Composer, $name, '1.0.0');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function blankNameProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'whitespace' => ['   '];
    }

    #[Test]
    #[DataProvider('acceptedVersionProvider')]
    public function acceptsAnyVersionTheRealWorldProduces(string $version): void
    {
        self::assertSame($version, (new PackageRef(Ecosystem::Composer, 'vendor/one', $version))->version);
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
        $one = new PackageRef(Ecosystem::Composer, 'vendor/one', '1.0.0');
        $other = new PackageRef(Ecosystem::Composer, 'vendor/one', '1.0.0');

        self::assertTrue($one->equals($other));
        self::assertSame($one->identity(), $other->identity());
    }

    #[Test]
    #[DataProvider('differingReferenceProvider')]
    public function referencesDifferingInAnyFieldAreNotEqual(PackageRef $other): void
    {
        $reference = new PackageRef(Ecosystem::Composer, 'vendor/one', '1.0.0');

        self::assertFalse($reference->equals($other));
        self::assertNotSame($reference->identity(), $other->identity());
    }

    /**
     * @return iterable<string, array{PackageRef}>
     */
    public static function differingReferenceProvider(): iterable
    {
        yield 'another ecosystem' => [new PackageRef(Ecosystem::Npm, 'vendor/one', '1.0.0')];
        yield 'another name' => [new PackageRef(Ecosystem::Composer, 'vendor/two', '1.0.0')];
        yield 'another version' => [new PackageRef(Ecosystem::Composer, 'vendor/one', '1.0.1')];
    }
}
