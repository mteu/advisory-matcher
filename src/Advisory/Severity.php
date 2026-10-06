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

namespace mteu\AdvisoryMatcher\Advisory;

enum Severity: string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';
    case Unknown = 'unknown';

    public function getPriority(): int
    {
        return match ($this) {
            self::Low => 1,
            self::Medium => 2,
            self::High, self::Unknown => 3,
            self::Critical => 4,
        };
    }

    public function isAtLeast(self $minimum): bool
    {
        return $this->getPriority() >= $minimum->getPriority();
    }

    public static function fromFeedValue(string $severity): self
    {
        return match (strtolower(trim($severity))) {
            'low', 'info', 'informational', 'none' => self::Low,
            'moderate', 'medium' => self::Medium,
            'high' => self::High,
            'critical' => self::Critical,
            default => self::Unknown,
        };
    }

    public static function fromCvssScore(float $score): self
    {
        return match (true) {
            $score >= 9.0 => self::Critical,
            $score >= 7.0 => self::High,
            $score >= 4.0 => self::Medium,
            default => self::Low,
        };
    }
}
