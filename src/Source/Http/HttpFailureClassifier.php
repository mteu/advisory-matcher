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

namespace mteu\AdvisoryMatcher\Source\Http;

use mteu\AdvisoryMatcher\Source\FailureReason;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Client\RequestExceptionInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * @internal
 */
final readonly class HttpFailureClassifier
{
    private const array TIMEOUT_PHRASES = [
        'timed out',
        'idle timeout reached',
        'max duration was reached',
    ];

    public function reasonForTransportFailure(ClientExceptionInterface $exception): FailureReason
    {
        return match (true) {
            $this->mentionsTimeout($exception) => FailureReason::Timeout,
            $exception instanceof NetworkExceptionInterface => FailureReason::Unreachable,
            $exception instanceof RequestExceptionInterface => FailureReason::Rejected,
            default => FailureReason::Unreachable,
        };
    }

    public function reasonForUnreadableBody(ResponseBodyUnreadable $exception): FailureReason
    {
        return $this->mentionsTimeout($exception) ? FailureReason::Timeout : FailureReason::Unreachable;
    }

    public function reasonForStatus(int $status): FailureReason
    {
        return match (true) {
            $status === 429 => FailureReason::RateLimited,
            $status >= 500 => FailureReason::Unreachable,
            default => FailureReason::Rejected,
        };
    }

    public function retryAfterSeconds(ResponseInterface $response): ?int
    {
        $retryAfter = trim($response->getHeaderLine('Retry-After'));

        if ($retryAfter === '' || !ctype_digit($retryAfter)) {
            return null;
        }

        return (int)$retryAfter;
    }

    private function mentionsTimeout(\Throwable $exception): bool
    {
        $message = $exception->getMessage();

        foreach (self::TIMEOUT_PHRASES as $phrase) {
            if (stripos($message, $phrase) !== false) {
                return true;
            }
        }

        return false;
    }
}
