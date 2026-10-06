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

use mteu\AdvisoryMatcher\Package\ComposerPackageNameValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(ComposerPackageNameValidator::class)]
final class ComposerPackageNameValidatorTest extends TestCase
{
    /**
     * @return \Generator<string, array{string}>
     */
    public static function installableNames(): \Generator
    {
        yield 'plain' => ['typo3/cms-core'];
        yield 'digits' => ['vendor2/pkg3'];
        yield 'dots and underscores' => ['vendor.name/pkg_name'];
        yield 'double hyphen' => ['vendor/pkg--name'];
        // Predates the lowercase convention, still installable — rejecting it
        // would leave a real package unmonitored.
        yield 'historically cased' => ['PHPMailer/PHPMailer'];
    }

    /**
     * @return \Generator<string, array{string}>
     */
    public static function namesNoPackagistPackageCouldHave(): \Generator
    {
        yield 'no vendor segment' => ['justaname'];
        yield 'empty' => [''];
        yield 'spaces' => ['vendor/pkg name'];
        yield 'two slashes' => ['vendor/sub/pkg'];
        yield 'leading separator' => ['-vendor/pkg'];
        yield 'trailing separator' => ['vendor/pkg-'];
        // The shape that made unencoded interpolation dangerous.
        yield 'forged query parameter' => ['evil/pkg&packages[]=dropped'];
        yield 'newline' => ["vendor/pkg\nvendor/other"];
    }

    #[Test]
    #[DataProvider('installableNames')]
    public function acceptsNamesComposerWouldInstall(string $packageName): void
    {
        self::assertTrue((new ComposerPackageNameValidator())->isValid($packageName));
    }

    #[Test]
    #[DataProvider('namesNoPackagistPackageCouldHave')]
    public function rejectsNamesNoPackagistPackageCouldHave(string $packageName): void
    {
        self::assertFalse((new ComposerPackageNameValidator())->isValid($packageName));
    }
}
