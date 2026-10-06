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

namespace mteu\AdvisoryMatcher\Tests\Unit\Source\Cache;

use Psr\SimpleCache\CacheInterface;

final class SimpleCacheDouble implements CacheInterface
{
    /**
     * @var array<string, mixed> Whatever the subject stored; PSR-16 values are untyped.
     */
    private array $values = [];

    /**
     * @var array<string, int|null>
     */
    private array $ttls = [];

    private int $writeCalls = 0;

    private bool $refusesWrites = false;

    public function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->values) ? $this->values[$key] : $default;
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        ++$this->writeCalls;

        return $this->write($key, $value, $ttl);
    }

    public function delete(string $key): bool
    {
        unset($this->values[$key], $this->ttls[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->values = [];
        $this->ttls = [];

        return true;
    }

    /**
     * @param iterable<string> $keys
     * @return iterable<string, mixed>
     */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $values = [];

        foreach ($keys as $key) {
            $values[$key] = $this->get($key, $default);
        }

        return $values;
    }

    /**
     * @param iterable<mixed, mixed> $values
     */
    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        ++$this->writeCalls;
        $stored = true;

        foreach ($values as $key => $value) {
            if (is_string($key)) {
                $stored = $this->write($key, $value, $ttl) && $stored;
            }
        }

        return $stored;
    }

    /**
     * @param iterable<string> $keys
     */
    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->values);
    }

    /**
     * @return list<string>
     */
    public function storedKeys(): array
    {
        return array_keys($this->values);
    }

    public function ttlOf(string $key): ?int
    {
        return $this->ttls[$key] ?? null;
    }

    public function writeCalls(): int
    {
        return $this->writeCalls;
    }

    public function refuseWrites(): void
    {
        $this->refusesWrites = true;
    }

    private function write(string $key, mixed $value, null|int|\DateInterval $ttl): bool
    {
        if ($this->refusesWrites) {
            return false;
        }

        $this->values[$key] = $value;
        $this->ttls[$key] = $ttl instanceof \DateInterval
            ? (new \DateTimeImmutable('@0'))->add($ttl)->getTimestamp()
            : $ttl;

        return true;
    }
}
