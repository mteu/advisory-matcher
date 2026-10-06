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

use Psr\Http\Message\StreamInterface;

final class ResettingStream implements StreamInterface
{
    private int $reads = 0;

    public function __construct(
        private readonly string $failureMessage = 'Connection reset by peer',
    ) {
    }

    public function read(int $length): string
    {
        ++$this->reads;

        if ($this->reads > 1) {
            throw new \RuntimeException($this->failureMessage);
        }

        return '{"partial": ';
    }

    public function eof(): bool
    {
        return false;
    }

    public function __toString(): string
    {
        throw new \LogicException('A resetting body cannot be read whole.');
    }

    public function getContents(): string
    {
        throw new \LogicException('A resetting body cannot be read whole.');
    }

    public function close(): void
    {
    }

    public function detach(): null
    {
        return null;
    }

    public function getSize(): ?int
    {
        return null;
    }

    public function tell(): int
    {
        return 0;
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        throw new \LogicException('A resetting body is not seekable.');
    }

    public function rewind(): void
    {
        throw new \LogicException('A resetting body is not seekable.');
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new \LogicException('A resetting body is not writable.');
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function getMetadata(?string $key = null): mixed
    {
        return $key === null ? [] : null;
    }
}
