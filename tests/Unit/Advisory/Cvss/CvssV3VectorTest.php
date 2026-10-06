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

namespace mteu\AdvisoryMatcher\Tests\Unit\Advisory\Cvss;

use mteu\AdvisoryMatcher\Advisory\Cvss\CvssV3Vector;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(CvssV3Vector::class)]
final class CvssV3VectorTest extends TestCase
{
    #[Test]
    #[DataProvider('scoredVectors')]
    public function computesTheBaseScoreTheSpecificationDefines(string $vector, float $expected): void
    {
        self::assertSame($expected, CvssV3Vector::fromString($vector)->baseScore());
    }

    /**
     * @return iterable<string, array{string, float}>
     */
    public static function scoredVectors(): iterable
    {
        yield 'everything high, scope changed' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0];
        yield 'everything high, scope unchanged' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8];
        yield 'low privileges, scope changed' => ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 9.9];
        yield 'low privileges, scope unchanged' => ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8];
        yield 'availability only' => ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5];
        yield 'reflected XSS' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1];
        yield 'local information disclosure' => ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 5.5];
        yield 'hard to reach, low impact' => ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N', 3.7];
        yield 'no impact at all' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0];
        yield 'temporal metrics do not change the base score' => [
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C',
            9.8,
        ];
        yield 'metrics in another order' => ['CVSS:3.1/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N/S:U', 9.8];
    }

    #[Test]
    #[DataProvider('unreadableVectors')]
    public function refusesAVectorThatIsNotCvss3(string $vector): void
    {
        $this->expectException(\InvalidArgumentException::class);

        CvssV3Vector::fromString($vector);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unreadableVectors(): iterable
    {
        yield 'empty' => [''];
        yield 'a CVSS 4 vector' => ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'];
        yield 'a CVSS 2 vector' => ['AV:N/AC:L/Au:N/C:P/I:P/A:P'];
        yield 'a base metric missing' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H'];
        yield 'a value the metric does not have' => ['CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'];
        yield 'a metric stated twice' => ['CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'];
        yield 'a part that is not a metric' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/garbage'];
        yield 'a numeric score' => ['9.8'];
    }
}
