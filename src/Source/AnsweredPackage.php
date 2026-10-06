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

use mteu\AdvisoryMatcher\Advisory\Advisory;

final readonly class AnsweredPackage
{
    /**
     * @param list<Advisory> $advisories
     */
    public function __construct(
        public PackageRef $package,
        public array $advisories = [],
    ) {
        if (!array_is_list($advisories)) {
            throw new \InvalidArgumentException('An answer\'s advisories have to be a list.');
        }
    }
}
