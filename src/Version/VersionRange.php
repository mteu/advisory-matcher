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

namespace mteu\AdvisoryMatcher\Version;

final readonly class VersionRange
{
    // Operators, separators and whitespace are refused so a bound can never
    // change the meaning of the constraint it is rendered into.
    private const string BOUND_PATTERN = '/\A[0-9A-Za-z][0-9A-Za-z.+~_:!-]*\z/';

    /**
     * Every bound is optional; '' leaves that side open.
     *
     * @param string $from inclusive lower bound (>=)
     * @param string $after exclusive lower bound (>)
     * @param string $before exclusive upper bound (<), the version that fixes this range
     * @param string $through inclusive upper bound (<=)
     */
    public function __construct(
        public string $from = '',
        public string $after = '',
        public string $before = '',
        public string $through = '',
    ) {
        if ($from !== '' && $after !== '') {
            throw new \InvalidArgumentException('A version range has at most one lower bound.');
        }

        if ($before !== '' && $through !== '') {
            throw new \InvalidArgumentException('A version range has at most one upper bound.');
        }

        foreach ([$from, $after, $before, $through] as $bound) {
            if ($bound !== '' && preg_match(self::BOUND_PATTERN, $bound) !== 1) {
                throw new \InvalidArgumentException(sprintf('"%s" is not a version a range can be bounded by.', $bound));
            }
        }
    }

    public static function exactly(string $version): self
    {
        return new self(from: $version, through: $version);
    }

    public function isExactVersion(): bool
    {
        return $this->from !== '' && $this->from === $this->through;
    }

    /**
     * @return list<string>
     */
    public function bounds(): array
    {
        return array_values(array_filter(
            [$this->from, $this->after, $this->before, $this->through],
            static fn (string $bound): bool => $bound !== '',
        ));
    }

    public function toComposerConstraint(): string
    {
        if ($this->isExactVersion()) {
            return $this->from;
        }

        $conditions = array_filter([
            $this->from !== '' ? '>=' . $this->from : '',
            $this->after !== '' ? '>' . $this->after : '',
            $this->before !== '' ? '<' . $this->before : '',
            $this->through !== '' ? '<=' . $this->through : '',
        ], static fn (string $condition): bool => $condition !== '');

        return $conditions === [] ? '*' : implode(',', $conditions);
    }
}
