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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Ecosystem::class)]
final class EcosystemTest extends TestCase
{
    #[Test]
    #[DataProvider('packageUrlTypeProvider')]
    public function resolvesPackageUrlTypeToEcosystem(string $type, Ecosystem $expected): void
    {
        self::assertSame($expected, Ecosystem::fromPackageUrlType($type));
    }

    /**
     * @return iterable<string, array{string, Ecosystem}>
     */
    public static function packageUrlTypeProvider(): iterable
    {
        yield 'composer' => ['composer', Ecosystem::Composer];
        yield 'packagist alias' => ['packagist', Ecosystem::Composer];
        yield 'npm' => ['npm', Ecosystem::Npm];
        yield 'node alias' => ['node', Ecosystem::Npm];
        yield 'php' => ['php', Ecosystem::Php];

        yield 'uppercase is normalised' => ['COMPOSER', Ecosystem::Composer];
        yield 'surrounding whitespace is trimmed' => ['  npm  ', Ecosystem::Npm];
    }

    #[Test]
    #[DataProvider('unrecognisedTypeProvider')]
    public function treatsUnrecognisedTypeAsUnknown(string $type): void
    {
        self::assertSame(Ecosystem::Unknown, Ecosystem::fromPackageUrlType($type));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unrecognisedTypeProvider(): iterable
    {
        yield 'empty string' => [''];
        yield 'whitespace only' => ['   '];
        yield 'distribution package type' => ['deb'];
        yield 'alpine package type' => ['apk'];
        yield 'container image type' => ['oci'];
        yield 'nonsense' => ['not-an-ecosystem'];
        yield 'pypi, which no source covers' => ['pypi'];
        yield 'maven, which no source covers' => ['maven'];
    }

    #[Test]
    public function namesEveryEcosystemForDisplay(): void
    {
        foreach (Ecosystem::cases() as $ecosystem) {
            self::assertNotSame('', $ecosystem->getDisplayName());
        }
    }

    #[Test]
    public function usesEachEcosystemsOwnSpellingForDisplay(): void
    {
        self::assertSame('npm', Ecosystem::Npm->getDisplayName());
        self::assertSame('PHP', Ecosystem::Php->getDisplayName());
    }

    #[Test]
    public function everyCaseRoundTripsThroughItsBackingValue(): void
    {
        foreach (Ecosystem::cases() as $ecosystem) {
            self::assertSame($ecosystem, Ecosystem::fromPackageUrlType($ecosystem->value));
        }
    }
}
