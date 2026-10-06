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

final readonly class PackageRef
{
    public function __construct(
        public Ecosystem $ecosystem,
        public string $name,
        public string $version,
    ) {
        if (trim($name) === '') {
            throw new \InvalidArgumentException('A package reference needs a name.');
        }
    }

    public function identity(): string
    {
        return $this->ecosystem->value . '|' . $this->name . '|' . $this->version;
    }

    public function equals(self $other): bool
    {
        return $this->identity() === $other->identity();
    }
}
