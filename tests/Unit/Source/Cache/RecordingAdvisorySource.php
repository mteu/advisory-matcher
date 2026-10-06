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

namespace mteu\AdvisoryMatcher\Tests\Unit\Source\Cache;

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\AdvisoryBatch;
use mteu\AdvisoryMatcher\Source\AdvisorySource;
use mteu\AdvisoryMatcher\Source\AnsweredPackage;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Source\SourceFailure;

final class RecordingAdvisorySource implements AdvisorySource
{
    /**
     * @var list<list<string>>
     */
    private array $calls = [];

    /**
     * @var array<string, list<Advisory>>
     */
    private array $advisoriesByName = [];

    /**
     * @var array<string, list<Advisory>> keyed by `name@version`
     */
    private array $advisoriesByVersion = [];

    /**
     * @var list<string>
     */
    private array $unknownNames = [];

    private ?FailureReason $failure = null;

    /**
     * @param list<Ecosystem> $coveredEcosystems
     */
    public function __construct(
        private readonly array $coveredEcosystems = [Ecosystem::Composer],
    ) {
    }

    /**
     * @param list<Advisory> $advisories
     */
    public function withAdvisories(string $packageName, array $advisories): self
    {
        $this->advisoriesByName[$packageName] = $advisories;

        return $this;
    }

    /**
     * @param list<Advisory> $advisories
     */
    public function withAdvisoriesAt(string $packageName, string $version, array $advisories): self
    {
        $this->advisoriesByVersion[$packageName . '@' . $version] = $advisories;

        return $this;
    }

    public function notKnowing(string $packageName): self
    {
        $this->unknownNames[] = $packageName;

        return $this;
    }

    public function failingWith(FailureReason $reason): self
    {
        $this->failure = $reason;

        return $this;
    }

    /**
     * @return list<list<string>>
     */
    public function calls(): array
    {
        return $this->calls;
    }

    public function name(): string
    {
        return 'Recorded';
    }

    public function coveredEcosystems(): array
    {
        return $this->coveredEcosystems;
    }

    public function advisoriesFor(array $packages): AdvisoryBatch
    {
        $this->calls[] = array_map(static fn (PackageRef $package): string => $package->name, $packages);

        if ($this->failure !== null) {
            return new AdvisoryBatch(failures: [
                new SourceFailure($this->name(), Ecosystem::Composer, $this->failure, 'recorded failure'),
            ]);
        }

        $answeredFor = [];

        foreach ($packages as $package) {
            if (in_array($package->name, $this->unknownNames, true)) {
                continue;
            }

            $answeredFor[] = new AnsweredPackage(
                $package,
                advisories: $this->advisoriesByVersion[$package->name . '@' . $package->version]
                    ?? $this->advisoriesByName[$package->name]
                    ?? [],
            );
        }

        return new AdvisoryBatch(answeredFor: $answeredFor);
    }
}
