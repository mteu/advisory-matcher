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

use Psr\Log\LoggerInterface;

final class CollectingLogger implements LoggerInterface
{
    /**
     * @var list<array{level: string, message: string, context: array<mixed>}>
     */
    private array $records = [];

    public function emergency(\Stringable|string $message, array $context = []): void
    {
        $this->log('emergency', $message, $context);
    }

    public function alert(\Stringable|string $message, array $context = []): void
    {
        $this->log('alert', $message, $context);
    }

    public function critical(\Stringable|string $message, array $context = []): void
    {
        $this->log('critical', $message, $context);
    }

    public function error(\Stringable|string $message, array $context = []): void
    {
        $this->log('error', $message, $context);
    }

    public function warning(\Stringable|string $message, array $context = []): void
    {
        $this->log('warning', $message, $context);
    }

    public function notice(\Stringable|string $message, array $context = []): void
    {
        $this->log('notice', $message, $context);
    }

    public function info(\Stringable|string $message, array $context = []): void
    {
        $this->log('info', $message, $context);
    }

    public function debug(\Stringable|string $message, array $context = []): void
    {
        $this->log('debug', $message, $context);
    }

    /**
     * @param mixed $level PSR-3 leaves the level's type open.
     */
    public function log($level, \Stringable|string $message, array $context = []): void
    {
        $this->records[] = [
            'level' => is_string($level) ? $level : get_debug_type($level),
            'message' => (string)$message,
            'context' => $context,
        ];
    }

    public function transcript(): string
    {
        return json_encode($this->records, JSON_THROW_ON_ERROR | JSON_PARTIAL_OUTPUT_ON_ERROR);
    }

    /**
     * @return list<array{level: string, message: string, context: array<mixed>}>
     */
    public function records(): array
    {
        return $this->records;
    }
}
