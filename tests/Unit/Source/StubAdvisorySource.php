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

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\AdvisoryBatch;
use mteu\AdvisoryMatcher\Source\AdvisorySource;
use mteu\AdvisoryMatcher\Source\AnsweredPackage;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Source\SourceFailure;

final class StubAdvisorySource implements AdvisorySource
{
    /**
     * @var list<PackageRef>
     */
    private array $asked = [];

    private int $calls = 0;

    /**
     * @param list<Ecosystem> $coveredEcosystems
     * @param array<string, list<Advisory>> $advisoriesByPackageName
     * @param list<SourceFailure> $failures
     */
    public function __construct(
        private readonly string $name,
        private readonly array $coveredEcosystems,
        private readonly array $advisoriesByPackageName = [],
        private readonly array $failures = [],
    ) {
    }

    /**
     * @return list<PackageRef>
     */
    public function askedAbout(): array
    {
        return $this->asked;
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
        $answeredFor = [];

        foreach ($packages as $package) {
            $this->asked[] = $package;

            if (!in_array($package->ecosystem, $this->coveredEcosystems, true)) {
                continue;
            }

            $answeredFor[] = new AnsweredPackage(
                $package,
                advisories: $this->advisoriesByPackageName[$package->name] ?? [],
            );
        }

        return new AdvisoryBatch(
            answeredFor: $answeredFor,
            failures: $this->failures,
        );
    }
}
