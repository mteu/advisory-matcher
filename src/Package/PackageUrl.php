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

/**
 * A canonical package URL that names a package but no version.
 *
 * Follows the purl specification more closely than packageurl-php does.
 * Composer names are lowercased and npm names keep their case.
 */
final readonly class PackageUrl
{
    // Built once because matching compares package URLs by it constantly.
    private string $canonical;

    private function __construct(
        public string $type,
        public string $namespace,
        public string $name,
    ) {
        if (trim($name) === '') {
            throw new \InvalidArgumentException('A package URL needs a name.');
        }

        $segments = $namespace === '' ? [] : explode('/', $namespace);
        $segments[] = $name;
        $this->canonical = 'pkg:' . $type . '/' . implode('/', array_map(self::encodeSegment(...), $segments));
    }

    /**
     * @param string $purl anything after the name is dropped
     * @throws \InvalidArgumentException
     */
    public static function fromString(string $purl): self
    {
        $parsed = self::parse($purl);

        return self::fromParsed($parsed, self::nameAsWritten($purl));
    }

    /**
     * @return string '' when the package URL names none
     * @throws \InvalidArgumentException
     */
    public static function versionIn(string $purl): string
    {
        return self::parse($purl)->getVersion() ?? '';
    }

    /**
     * @param string $packageName the name as its registry spells it, such as `symfony/console` or `@babel/core`
     * @throws \InvalidArgumentException
     */
    public static function fromPackageName(string $type, string $packageName): self
    {
        $separatorPosition = strrpos($packageName, '/');
        $namespace = $separatorPosition === false ? '' : substr($packageName, 0, $separatorPosition);
        $name = $separatorPosition === false ? $packageName : substr($packageName, $separatorPosition + 1);

        try {
            $built = new SpecPackageUrl($type, $name);
            $built->setNamespace($namespace === '' ? null : $namespace);
            $purl = $built->toString();
        } catch (\DomainException $exception) {
            throw new \InvalidArgumentException('Not a valid package URL.', 0, $exception);
        }

        // Building does not apply the per-type rules, parsing does.
        return self::fromParsed(self::parse($purl), $name);
    }

    public function packageName(): string
    {
        return $this->namespace === '' ? $this->name : $this->namespace . '/' . $this->name;
    }

    public function ecosystem(): Ecosystem
    {
        return match (true) {
            $this->type === 'composer' => Ecosystem::Composer,
            $this->type === 'npm' => Ecosystem::Npm,
            $this->type === 'generic' && $this->namespace === '' && $this->name === 'php' => Ecosystem::Php,
            default => Ecosystem::Unknown,
        };
    }

    public function toString(): string
    {
        return $this->canonical;
    }

    /**
     * @param string $version '' for none
     */
    public function toStringAtVersion(string $version): string
    {
        return $version === '' ? $this->toString() : $this->toString() . '@' . self::encodeSegment($version);
    }

    public function equals(self $other): bool
    {
        return $this->canonical === $other->canonical;
    }

    /**
     * @throws \InvalidArgumentException
     */
    private static function parse(string $purl): SpecPackageUrl
    {
        // The input is not echoed because exception messages end up in logs and views.
        try {
            $parsed = SpecPackageUrl::fromString($purl);
        } catch (\DomainException $exception) {
            throw new \InvalidArgumentException('Not a valid package URL.', 0, $exception);
        }

        if ($parsed === null) {
            throw new \InvalidArgumentException('Not a valid package URL.');
        }

        return $parsed;
    }

    private static function fromParsed(SpecPackageUrl $parsed, string $nameAsWritten): self
    {
        $type = $parsed->getType();
        $namespace = $parsed->getNamespace() ?? '';
        $name = $parsed->getName();

        return match ($type) {
            'composer' => new self($type, strtolower($namespace), strtolower($name)),
            // packageurl-php lowercases npm names, but feeds file mixed-case packages such as `JSONStream` under their spelling.
            'npm' => new self($type, $namespace, strcasecmp($nameAsWritten, $name) === 0 ? $nameAsWritten : $name),
            default => new self($type, $namespace, $name),
        };
    }

    private static function nameAsWritten(string $purl): string
    {
        $withoutSubpath = explode('#', $purl)[0];
        $withoutQualifiers = explode('?', $withoutSubpath)[0];
        $segments = explode('/', rtrim($withoutQualifiers, '/'));

        return rawurldecode(explode('@', end($segments))[0]);
    }

    private static function encodeSegment(string $segment): string
    {
        // As packageurl-php encodes it, so the result reads back unchanged.
        return strtr(rawurlencode($segment), ['%3A' => ':']);
    }
}
