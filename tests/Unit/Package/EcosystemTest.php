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
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Ecosystem::class)]
final class EcosystemTest extends TestCase
{
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
            self::assertSame($ecosystem, Ecosystem::from($ecosystem->value));
        }
    }
}
