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

use Psr\Http\Message\ResponseInterface;

/**
 * @internal
 */
final readonly class BoundedBodyReader
{
    public const int DEFAULT_MAX_BYTES = 25 * 1024 * 1024;

    private const int CHUNK_BYTES = 65536;

    public function __construct(
        private int $maxBytes = self::DEFAULT_MAX_BYTES,
    ) {
        if ($maxBytes < 1) {
            throw new \InvalidArgumentException('A body cap has to allow at least one byte.');
        }
    }

    /**
     * @throws ResponseTooLarge
     * @throws ResponseBodyUnreadable
     */
    public function read(ResponseInterface $response): string
    {
        $contentLength = $response->getHeaderLine('Content-Length');
        if ($contentLength !== '' && ctype_digit($contentLength) && (int)$contentLength > $this->maxBytes) {
            throw ResponseTooLarge::beyond($this->maxBytes);
        }

        try {
            return $this->readWithinCap($response);
        } catch (\RuntimeException $exception) {
            throw ResponseBodyUnreadable::because($exception);
        }
    }

    /**
     * @throws ResponseTooLarge
     * @throws \RuntimeException
     */
    private function readWithinCap(ResponseInterface $response): string
    {
        $stream = $response->getBody();
        $buffer = '';
        $read = 0;

        while (!$stream->eof()) {
            $chunk = $stream->read(self::CHUNK_BYTES);
            if ($chunk === '') {
                break;
            }

            $read += strlen($chunk);
            if ($read > $this->maxBytes) {
                throw ResponseTooLarge::beyond($this->maxBytes);
            }

            $buffer .= $chunk;
        }

        return $buffer;
    }
}
