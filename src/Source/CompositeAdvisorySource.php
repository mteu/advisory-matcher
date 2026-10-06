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
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final readonly class CompositeAdvisorySource implements AdvisorySource
{
    public const string NAME = 'Composite';

    /**
     * @param list<AdvisorySource> $sources
     */
    public function __construct(
        private array $sources,
        private LoggerInterface $logger = new NullLogger(),
        private AdvisoryDeduplicator $deduplicator = new AdvisoryDeduplicator(),
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function coveredEcosystems(): array
    {
        $covered = [];

        foreach ($this->sources as $source) {
            foreach ($source->coveredEcosystems() as $ecosystem) {
                $covered[$ecosystem->value] = $ecosystem;
            }
        }

        return array_values($covered);
    }

    public function advisoriesFor(array $packages): AdvisoryBatch
    {
        $batch = new AdvisoryBatch();

        foreach ($this->sources as $source) {
            $routed = $this->packagesCoveredBy($source, $packages);

            if ($routed !== []) {
                $batch = $batch->merge($this->askContainingDefects($source, $routed));
            }
        }

        return $this->deduplicator->deduplicate($batch);
    }

    /**
     * @param list<PackageRef> $packages
     * @return list<PackageRef>
     */
    private function packagesCoveredBy(AdvisorySource $source, array $packages): array
    {
        $covered = $source->coveredEcosystems();

        return array_values(array_filter(
            $packages,
            static fn (PackageRef $package): bool => in_array($package->ecosystem, $covered, true),
        ));
    }

    /**
     * @param non-empty-list<PackageRef> $packages
     */
    private function askContainingDefects(AdvisorySource $source, array $packages): AdvisoryBatch
    {
        try {
            return $source->advisoriesFor($packages);
        } catch (\Exception $defect) {
            // Only the message and not the exception because it carries the request that itself can carry a credential.
            $this->logger->error('An advisory source threw instead of answering.', [
                'source' => $source->name(),
                'exception' => $defect::class,
                'message' => $defect->getMessage(),
            ]);

            return new AdvisoryBatch(failures: $this->brokenFailuresFor($source, $packages, $defect));
        }
    }

    /**
     * @param non-empty-list<PackageRef> $packages
     * @return list<SourceFailure>
     */
    private function brokenFailuresFor(AdvisorySource $source, array $packages, \Exception $defect): array
    {
        /** @var array<string, Ecosystem> $ecosystems */
        $ecosystems = [];

        foreach ($packages as $package) {
            $ecosystems[$package->ecosystem->value] = $package->ecosystem;
        }

        $detail = sprintf('%s: %s', $defect::class, $defect->getMessage());

        return array_values(array_map(
            static fn (Ecosystem $ecosystem): SourceFailure => new SourceFailure(
                sourceName: $source->name(),
                ecosystem: $ecosystem,
                reason: FailureReason::Broken,
                detail: $detail,
            ),
            $ecosystems,
        ));
    }
}
