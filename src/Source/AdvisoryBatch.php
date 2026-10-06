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

final readonly class AdvisoryBatch
{
    /**
     * @var list<AnsweredPackage>
     */
    public array $answeredFor;

    /**
     * @var list<Advisory>
     */
    public array $advisories;

    /**
     * @var array<string, AnsweredPackage> keyed by {@see PackageRef::identity()}
     */
    private array $answersByPackage;

    /**
     * @param list<AnsweredPackage> $answeredFor
     * @param list<SourceFailure> $failures
     */
    public function __construct(
        array $answeredFor = [],
        public array $failures = [],
    ) {
        $answersByPackage = [];

        foreach ($answeredFor as $answer) {
            $identity = $answer->package->identity();
            $held = $answersByPackage[$identity] ?? null;
            $answersByPackage[$identity] = $held === null ? $answer : self::combineAnswers($held, $answer);
        }

        $this->answersByPackage = $answersByPackage;
        $this->answeredFor = array_values($answersByPackage);
        $this->advisories = array_merge(...array_map(
            static fn (AnsweredPackage $answer): array => $answer->advisories,
            $this->answeredFor,
        ));
    }

    public function isComplete(): bool
    {
        return $this->failures === [];
    }

    public function merge(self $other): self
    {
        return new self(
            answeredFor: [...$this->answeredFor, ...$other->answeredFor],
            failures: [...$this->failures, ...$other->failures],
        );
    }

    /**
     * @return list<Advisory>
     */
    public function advisoriesFor(PackageRef $package): array
    {
        return $this->answersByPackage[$package->identity()]->advisories ?? [];
    }

    public function wasAnsweredFor(PackageRef $package): bool
    {
        return array_key_exists($package->identity(), $this->answersByPackage);
    }

    /**
     * @param list<PackageRef> $packages
     * @return list<PackageRef>
     */
    public function unansweredAmong(array $packages): array
    {
        return array_values(array_filter(
            $packages,
            fn (PackageRef $package): bool => !$this->wasAnsweredFor($package),
        ));
    }

    private static function combineAnswers(AnsweredPackage $held, AnsweredPackage $incoming): AnsweredPackage
    {
        // Only the very same record is dropped, as when one package was asked about twice.
        // Two feeds' reports of one vulnerability are distinct records.
        $added = array_filter(
            $incoming->advisories,
            static fn (Advisory $advisory): bool => !in_array($advisory, $held->advisories, true),
        );

        return new AnsweredPackage(
            package: $held->package,
            advisories: [...$held->advisories, ...array_values($added)],
        );
    }
}
