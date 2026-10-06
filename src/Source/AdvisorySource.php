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

interface AdvisorySource
{
    public function name(): string;

    /**
     * @return list<Ecosystem>
     */
    public function coveredEcosystems(): array;

    /**
     * Feed outages are reported in AdvisoryBatch::$failures, but never thrown.
     * An exception means the source itself is broken. Packages outside coveredEcosystems() are neither answered nor failed.
     *
     * @param list<PackageRef> $packages
     */
    public function advisoriesFor(array $packages): AdvisoryBatch;
}
