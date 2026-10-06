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

use mteu\AdvisoryMatcher\Source\Http\UserAgent;
use Nyholm\Psr7\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(UserAgent::class)]
final class UserAgentTest extends TestCase
{
    #[Test]
    public function theLibraryDefaultNamesThePackageAndWhereToReachIt(): void
    {
        self::assertSame(
            'mteu/advisory-matcher (+https://github.com/mteu/advisory-matcher)',
            UserAgent::LIBRARY_DEFAULT,
        );
    }

    #[Test]
    public function setsTheHeaderOnARequest(): void
    {
        $request = (new UserAgent('acme-monitor/2.1'))->applyTo(new Request('GET', 'https://feed.example/'));

        self::assertSame('acme-monitor/2.1', $request->getHeaderLine('User-Agent'));
    }

    #[Test]
    public function replacesAUserAgentTheRequestAlreadyCarried(): void
    {
        $request = (new UserAgent('acme-monitor/2.1'))
            ->applyTo(new Request('GET', 'https://feed.example/', ['User-Agent' => 'GuzzleHttp/7']));

        self::assertSame(['acme-monitor/2.1'], $request->getHeader('User-Agent'));
    }

    #[Test]
    public function surroundingWhitespaceIsTrimmed(): void
    {
        $request = (new UserAgent("  acme-monitor/2.1\t"))->applyTo(new Request('GET', 'https://feed.example/'));

        self::assertSame('acme-monitor/2.1', $request->getHeaderLine('User-Agent'));
    }

    #[Test]
    public function anEmptyValueLeavesTheRequestAsItWas(): void
    {
        $request = new Request('GET', 'https://feed.example/');

        self::assertSame($request, (new UserAgent('  '))->applyTo($request));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function valuesThatCouldSmuggleAHeader(): iterable
    {
        yield 'a line feed' => ["acme\nX-Injected: 1"];
        yield 'a carriage return' => ["acme\rX-Injected: 1"];
        yield 'a null byte' => ["ac\0me"];
        yield 'a non-ASCII character' => ['acmé-monitor'];
    }

    #[Test]
    #[DataProvider('valuesThatCouldSmuggleAHeader')]
    public function aValueThatIsNotASafeHeaderIsRefused(string $value): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new UserAgent($value);
    }
}
