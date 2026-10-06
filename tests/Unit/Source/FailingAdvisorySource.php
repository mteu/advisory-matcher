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
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\SourceFailure;

final class FailingAdvisorySource implements AdvisorySource
{
    private int $calls = 0;

    /**
     * @param list<Ecosystem> $coveredEcosystems
     */
    public function __construct(
        private readonly string $name,
        private readonly array $coveredEcosystems,
        private readonly FailureReason $reason = FailureReason::Unreachable,
    ) {
    }

    public function timesAsked(): int
    {
        return $this->calls;
    }

    public function name(): string
    {
        return $this->name;
    }

    public function coveredEcosystems(): array
    {
        return $this->coveredEcosystems;
    }

    public function advisoriesFor(array $packages): AdvisoryBatch
    {
        $this->calls++;

        $failures = [];

        foreach ($packages as $package) {
            $failures[$package->ecosystem->value] ??= new SourceFailure(
                $this->name,
                $package->ecosystem,
                $this->reason,
                'feed down',
            );
        }

        return new AdvisoryBatch(failures: array_values($failures));
    }
}
