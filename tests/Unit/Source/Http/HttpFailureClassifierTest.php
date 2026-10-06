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

use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\Http\HttpFailureClassifier;
use mteu\AdvisoryMatcher\Source\Http\ResponseBodyUnreadable;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(HttpFailureClassifier::class)]
final class HttpFailureClassifierTest extends TestCase
{
    /**
     * @return \Generator<string, array{int, FailureReason}>
     */
    public static function statuses(): \Generator
    {
        yield 'rate limited' => [429, FailureReason::RateLimited];
        yield 'not found' => [404, FailureReason::Rejected];
        yield 'forbidden' => [403, FailureReason::Rejected];
        yield 'server error' => [500, FailureReason::Unreachable];
        yield 'unavailable' => [503, FailureReason::Unreachable];
    }

    #[Test]
    #[DataProvider('statuses')]
    public function aStatusOutside2xxReadsAsTheReasonACallerActsOn(int $status, FailureReason $expected): void
    {
        self::assertSame($expected, (new HttpFailureClassifier())->reasonForStatus($status));
    }

    #[Test]
    #[DataProvider('unreadableBodies')]
    public function aBodyThatBrokeOffIsANetworkFailureACallerMayRetry(
        string $message,
        FailureReason $expected,
    ): void {
        $reason = (new HttpFailureClassifier())->reasonForUnreadableBody(
            ResponseBodyUnreadable::because(new \RuntimeException($message)),
        );

        self::assertSame($expected, $reason);
        self::assertTrue($reason->isTransient());
    }

    /**
     * @return \Generator<string, array{string, FailureReason}>
     */
    public static function unreadableBodies(): \Generator
    {
        yield 'connection reset' => ['Connection reset by peer', FailureReason::Unreachable];
        yield 'timed out mid-body' => [
            'cURL error 28: Operation timed out after 30000 milliseconds',
            FailureReason::Timeout,
        ];
        yield 'idle mid-body, Symfony' => [
            'Idle timeout reached for "https://api.osv.dev/v1/querybatch".',
            FailureReason::Timeout,
        ];
    }

    #[Test]
    #[DataProvider('transportFailures')]
    public function aTimeoutIsToldApartFromARefusedConnection(string $message, FailureReason $expected): void
    {
        $failure = new NetworkFailure(new Request('GET', 'https://feed.example/'), $message);

        self::assertSame($expected, (new HttpFailureClassifier())->reasonForTransportFailure($failure));
    }

    /**
     * @return \Generator<string, array{string, FailureReason}>
     */
    public static function transportFailures(): \Generator
    {
        yield 'cURL, whole request' => ['cURL error 28: Operation timed out after 30001 milliseconds', FailureReason::Timeout];
        yield 'cURL, connect' => ['cURL error 28: Connection timed out after 5001 milliseconds', FailureReason::Timeout];
        yield 'Symfony, idle' => ['Idle timeout reached for "https://api.osv.dev/v1/querybatch".', FailureReason::Timeout];
        yield 'Symfony, total' => ['Max duration was reached for "https://api.osv.dev/v1/querybatch".', FailureReason::Timeout];
        yield 'refused' => ['Connection refused', FailureReason::Unreachable];
        yield 'refused, timeout in the URL' => [
            'Failed to connect to "https://timeout.example/timeout": Connection refused',
            FailureReason::Unreachable,
        ];
    }

    #[Test]
    public function retryAfterInSecondsIsRead(): void
    {
        self::assertSame(
            120,
            (new HttpFailureClassifier())->retryAfterSeconds(new Response(429, ['Retry-After' => '120'])),
        );
    }

    /**
     * @return \Generator<string, array{array<string, string>}>
     */
    public static function retryAfterHeadersThatGiveNoAdvice(): \Generator
    {
        yield 'absent' => [[]];
        yield 'an HTTP date' => [['Retry-After' => 'Wed, 21 Oct 2026 07:28:00 GMT']];
        yield 'negative' => [['Retry-After' => '-5']];
    }

    /**
     * @param array<string, string> $headers
     */
    #[Test]
    #[DataProvider('retryAfterHeadersThatGiveNoAdvice')]
    public function aRetryAfterThatIsNotDeltaSecondsIsNoAdviceRatherThanGuessed(array $headers): void
    {
        self::assertNull((new HttpFailureClassifier())->retryAfterSeconds(new Response(429, $headers)));
    }
}
