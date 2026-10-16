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

namespace mteu\AdvisoryMatcher\Package;

use PackageUrl\PackageUrl as SpecPackageUrl;
use PackageUrl\PackageUrlParser;

/**
 * A package's identity as a canonical package URL without version,
 * qualifiers or subpath. Two spellings of one package, such as `@scope` and
 * `%40scope`, come out as the same {@see toString()}.
 */
final readonly class PackageUrl
{
    private const string TYPE_PATTERN = '/^[a-z][a-z0-9.+-]*$/D';

    // Earlier releases accepted these as aliases. The purl type registry
    // defines none of them, so a package URL carrying one names nothing.
    private const array UNREGISTERED_TYPES = ['packagist', 'node', 'php'];

    /**
     * @param string $namespace '' for a package without one, such as an unscoped npm package
     */
    private function __construct(
        public string $type,
        public string $namespace,
        public string $name,
    ) {
        if (preg_match(self::TYPE_PATTERN, $type) !== 1 || in_array($type, self::UNREGISTERED_TYPES, true)) {
            throw new \InvalidArgumentException('A package URL needs a valid, registered type.');
        }

        if ($name === '' || str_contains($name, '/')) {
            throw new \InvalidArgumentException('A package URL needs a name without a slash.');
        }

        if ($namespace !== '' && in_array('', explode('/', $namespace), true)) {
            throw new \InvalidArgumentException('A package URL namespace cannot have an empty segment.');
        }
    }

    /**
     * @throws \InvalidArgumentException
     */
    public static function fromString(string $purl): self
    {
        // The input is never echoed: it comes from SBOMs and stored records,
        // and an exception message ends up in logs and backend views.
        try {
            $parsed = SpecPackageUrl::fromString($purl);
        } catch (\DomainException $exception) {
            throw new \InvalidArgumentException('Not a valid package URL.', 0, $exception);
        }

        if ($parsed === null) {
            throw new \InvalidArgumentException('Not a valid package URL.');
        }

        $name = $parsed->getName();
        if ($parsed->getType() === 'npm') {
            // packageurl-php lowercases npm names. The current specification
            // keeps their case, since legacy packages such as JSONStream are
            // mixed-case on the registry.
            $parser = new PackageUrlParser();
            $name = $parser->normalizeName($parser->parse($purl)['name'], null) ?? $name;
        }

        return self::canonical($parsed->getType(), $parsed->getNamespace() ?? '', $name);
    }

    /**
     * @param string $packageName the name in its ecosystem's own spelling, namespace and name joined by a slash, such as `symfony/console` or `@babel/core`
     * @throws \InvalidArgumentException
     */
    public static function fromPackageName(string $type, string $packageName): self
    {
        $separatorPosition = strrpos($packageName, '/');

        if ($separatorPosition === false) {
            return self::canonical(strtolower($type), '', $packageName);
        }

        if ($separatorPosition === 0) {
            throw new \InvalidArgumentException('A package URL namespace cannot have an empty segment.');
        }

        return self::canonical(
            strtolower($type),
            substr($packageName, 0, $separatorPosition),
            substr($packageName, $separatorPosition + 1),
        );
    }

    public function packageName(): string
    {
        return $this->namespace === '' ? $this->name : $this->namespace . '/' . $this->name;
    }

    public function toString(): string
    {
        $namespace = $this->namespace === ''
            ? ''
            : implode('/', array_map(self::encodeSegment(...), explode('/', $this->namespace))) . '/';

        return 'pkg:' . $this->type . '/' . $namespace . self::encodeSegment($this->name);
    }

    public function equals(self $other): bool
    {
        return $this->type === $other->type
            && $this->namespace === $other->namespace
            && $this->name === $other->name;
    }

    private static function canonical(string $type, string $namespace, string $name): self
    {
        if ($type === 'composer') {
            return new self($type, strtolower($namespace), strtolower($name));
        }

        return new self($type, $namespace, $name);
    }

    private static function encodeSegment(string $segment): string
    {
        // The specification leaves the colon unencoded.
        return str_replace('%3A', ':', rawurlencode($segment));
    }
}
