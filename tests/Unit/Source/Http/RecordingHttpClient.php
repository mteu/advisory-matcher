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

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class RecordingHttpClient implements ClientInterface
{
    /**
     * @var list<RequestInterface>
     */
    private array $sent = [];

    /**
     * @param list<ResponseInterface|ClientExceptionInterface> $answers
     */
    public function __construct(
        private array $answers = [],
    ) {
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->sent[] = $request;

        $answer = array_shift($this->answers);

        if ($answer === null) {
            throw new \LogicException('The client was sent more requests than the test queued answers for.');
        }

        if ($answer instanceof ClientExceptionInterface) {
            throw $answer;
        }

        return $answer;
    }

    /**
     * @return list<RequestInterface>
     */
    public function sentRequests(): array
    {
        return $this->sent;
    }
}
