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

namespace mteu\AdvisoryMatcher\Source;

use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Package\PackageUrl;

final readonly class PackageRef
{
    public Ecosystem $ecosystem;

    /**
     * The name as the package's registry spells it, which is what a source asks its feed about.
     */
    public string $name;

    // Built once: batches and matching key and compare references by it.
    private string $canonical;

    public function __construct(
        public PackageUrl $package,
        public string $version,
    ) {
        $this->ecosystem = $package->ecosystem();
        $this->name = $package->packageName();
        $this->canonical = $package->toStringAtVersion($version);
    }

    /**
     * @param string $purl a package URL; one without a version gives a reference without one
     * @throws \InvalidArgumentException
     */
    public static function fromString(string $purl): self
    {
        return new self(PackageUrl::fromString($purl), PackageUrl::versionIn($purl));
    }

    public function toString(): string
    {
        return $this->canonical;
    }

    public function identity(): string
    {
        return $this->canonical;
    }

    public function equals(self $other): bool
    {
        return $this->canonical === $other->canonical;
    }
}
