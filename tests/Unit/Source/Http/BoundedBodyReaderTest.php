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

namespace mteu\AdvisoryMatcher\Tests\Unit\Source\Http;

use mteu\AdvisoryMatcher\Source\Http\BoundedBodyReader;
use mteu\AdvisoryMatcher\Source\Http\ResponseBodyUnreadable;
use mteu\AdvisoryMatcher\Source\Http\ResponseTooLarge;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(BoundedBodyReader::class)]
#[CoversClass(ResponseTooLarge::class)]
#[CoversClass(ResponseBodyUnreadable::class)]
final class BoundedBodyReaderTest extends TestCase
{
    #[Test]
    public function aBodyWithinTheCapIsReadWhole(): void
    {
        self::assertSame('{"results": []}', (new BoundedBodyReader(1024))->read(new Response(200, [], '{"results": []}')));
    }

    #[Test]
    public function aClaimedLengthOverTheCapIsRefusedBeforeReading(): void
    {
        $body = new EndlessStream();

        try {
            (new BoundedBodyReader(2 * 1_048_576))->read(
                (new Response(200, ['Content-Length' => (string)(3 * 1_048_576)]))->withBody($body),
            );
            self::fail('A body claiming more than the cap was read.');
        } catch (ResponseTooLarge $exception) {
            self::assertSame('The response exceeds the 2 MiB cap.', $exception->getMessage());
        }

        self::assertSame(0, $body->reads());
    }

    #[Test]
    public function aBodyThatLiesAboutItsLengthIsStillStoppedAtTheCap(): void
    {
        $body = new EndlessStream();

        $this->expectException(ResponseTooLarge::class);

        try {
            (new BoundedBodyReader(65536 * 3))->read((new Response(200, ['Content-Length' => '10']))->withBody($body));
        } finally {
            self::assertSame(4, $body->reads());
        }
    }

    #[Test]
    public function aBodyThatBreaksOffMidReadIsReportedAsUnreadable(): void
    {
        try {
            (new BoundedBodyReader())->read((new Response(200))->withBody(new ResettingStream('Connection reset by peer')));
            self::fail('A body that broke off mid-read was returned as complete.');
        } catch (ResponseBodyUnreadable $exception) {
            self::assertSame('The response body could not be read: Connection reset by peer', $exception->getMessage());
            self::assertInstanceOf(\RuntimeException::class, $exception->getPrevious());
        }
    }

    #[Test]
    public function aCapOfNothingIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new BoundedBodyReader(0);
    }
}
