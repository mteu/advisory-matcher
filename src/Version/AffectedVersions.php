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

final readonly class AffectedVersions
{
    // Two-character operators first, so `>=` is not read as `>` and `=1.0`.
    private const array BOUNDS_BY_OPERATOR = [
        '>=' => ['from'],
        '<=' => ['through'],
        '==' => ['from', 'through'],
        '>' => ['after'],
        '<' => ['before'],
        '=' => ['from', 'through'],
    ];

    /**
     * @var list<VersionRange>
     */
    public array $ranges;

    /**
     * An empty list states nothing about which versions are affected.
     *
     * @param list<VersionRange> $ranges
     */
    public function __construct(array $ranges = [])
    {
        $distinct = [];

        foreach ($ranges as $range) {
            $distinct[$range->toComposerConstraint()] ??= $range;
        }

        $this->ranges = array_values($distinct);
    }

    /**
     * Reads the subset of Composer's constraint syntax that advisory feeds use.
     *
     * @throws \InvalidArgumentException for anything outside that subset, such as `^`, `~` or `!=`
     */
    public static function fromComposerConstraint(string $constraint): self
    {
        $ranges = [];

        foreach (self::split('/\|\|?/', $constraint) as $branch) {
            if (trim($branch) !== '') {
                $ranges[] = self::rangeFrom($branch);
            }
        }

        return new self($ranges);
    }

    public function isEmpty(): bool
    {
        return $this->ranges === [];
    }

    public function union(self $other): self
    {
        return new self([...$this->ranges, ...$other->ranges]);
    }

    /**
     * @return list<string>
     */
    public function fixedVersions(): array
    {
        return array_values(array_filter(array_map(
            static fn (VersionRange $range): string => $range->before,
            $this->ranges,
        ), static fn (string $version): bool => $version !== ''));
    }

    public function toComposerConstraint(): string
    {
        return implode(' || ', array_map(
            static fn (VersionRange $range): string => $range->toComposerConstraint(),
            $this->ranges,
        ));
    }

    private static function rangeFrom(string $branch): VersionRange
    {
        $joined = preg_replace('/(>=|<=|==|>|<|=)\s+/', '$1', trim($branch)) ?? '';
        $conditions = self::split('/[\s,]+/', $joined);

        if ($conditions === []) {
            // Only separators: reading it as "every version" would turn junk into an advisory against everything.
            throw new \InvalidArgumentException(sprintf('"%s" names no version condition.', $branch));
        }

        $bounds = [];

        foreach ($conditions as $condition) {
            if ($condition === '*') {
                continue;
            }

            [$names, $version] = self::boundsNamedBy($condition);

            foreach ($names as $name) {
                if (array_key_exists($name, $bounds)) {
                    throw new \InvalidArgumentException(sprintf('"%s" bounds the same side twice.', $branch));
                }

                $bounds[$name] = $version;
            }
        }

        return new VersionRange(
            from: $bounds['from'] ?? '',
            after: $bounds['after'] ?? '',
            before: $bounds['before'] ?? '',
            through: $bounds['through'] ?? '',
        );
    }

    /**
     * @return array{list<string>, string}
     */
    private static function boundsNamedBy(string $condition): array
    {
        foreach (self::BOUNDS_BY_OPERATOR as $operator => $names) {
            if (str_starts_with($condition, $operator)) {
                $version = substr($condition, strlen($operator));

                if ($version === '') {
                    throw new \InvalidArgumentException(sprintf('"%s" compares against no version.', $condition));
                }

                return [$names, $version];
            }
        }

        return [['from', 'through'], $condition];
    }

    /**
     * @return list<string>
     */
    private static function split(string $pattern, string $subject): array
    {
        $pieces = preg_split($pattern, $subject, -1, PREG_SPLIT_NO_EMPTY);

        return $pieces === false ? [] : $pieces;
    }
}
