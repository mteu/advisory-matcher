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

namespace mteu\AdvisoryMatcher\Tests\Unit\Source;

use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\AdvisoryBatch;
use mteu\AdvisoryMatcher\Source\AdvisorySource;

final readonly class PresetBatchAdvisorySource implements AdvisorySource
{
    public function __construct(
        private AdvisoryBatch $batch,
    ) {
    }

    public function name(): string
    {
        return 'Preset';
    }

    public function coveredEcosystems(): array
    {
        return [Ecosystem::Composer];
    }

    public function advisoriesFor(array $packages): AdvisoryBatch
    {
        return $this->batch;
    }
}
