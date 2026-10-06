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

namespace mteu\AdvisoryMatcher\Source\Osv;

use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\PackageRef;

/**
 * @internal
 */
final readonly class OsvQuery
{
    /**
     * @param non-empty-list<PackageRef> $packages
     */
    public function __construct(
        public Ecosystem $ecosystem,
        public string $name,
        public array $packages,
    ) {
        self::labelFor($ecosystem);

        foreach ($packages as $package) {
            if ($package->ecosystem !== $ecosystem || $package->name !== $name) {
                throw new \InvalidArgumentException('Every package reference in a query has to ask the query\'s own question.');
            }
        }
    }

    public static function labelFor(Ecosystem $ecosystem): string
    {
        return match ($ecosystem) {
            Ecosystem::Composer => 'Packagist',
            Ecosystem::Npm => 'npm',
            Ecosystem::Php, Ecosystem::Unknown => throw new \InvalidArgumentException(
                sprintf('OSV has no ecosystem for "%s".', $ecosystem->value),
            ),
        };
    }

    public function label(): string
    {
        return self::labelFor($this->ecosystem);
    }
}
