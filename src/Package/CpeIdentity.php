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

/**
 * @internal
 */
final readonly class CpeIdentity
{
    private const int TRAILING_ATTRIBUTES = 7;

    public function __construct(
        public string $part,
        public string $vendor,
        public string $product,
    ) {
        if (trim($part) === '' || trim($vendor) === '' || trim($product) === '') {
            throw new \InvalidArgumentException('A CPE identity needs a part, a vendor and a product.');
        }
    }

    public static function application(string $vendor, string $product): self
    {
        return new self('a', $vendor, $product);
    }

    public static function forPackage(PackageUrl $package): ?self
    {
        return match ($package->ecosystem()) {
            Ecosystem::Php => self::application('php', 'php'),
            Ecosystem::Platform => PlatformProduct::from($package->name)->cpeIdentity(),
            Ecosystem::Composer, Ecosystem::Npm, Ecosystem::Unknown => null,
        };
    }

    public function nameForVersion(string $version): string
    {
        $release = $this->releaseOf($version);

        if ($release === '') {
            return '';
        }

        return implode(':', [
            'cpe',
            '2.3',
            $this->part,
            $this->vendor,
            $this->product,
            $release,
            ...array_fill(0, self::TRAILING_ATTRIBUTES, '*'),
        ]);
    }

    public function criteriaPrefix(): string
    {
        return sprintf('cpe:2.3:%s:%s:%s:', $this->part, $this->vendor, $this->product);
    }

    public function releaseOf(string $version): string
    {
        if (preg_match('/^v?(\d+(?:\.\d+)*)/', trim($version), $matches) !== 1) {
            return '';
        }

        return $matches[1];
    }
}
