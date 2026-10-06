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
use mteu\AdvisoryMatcher\Source\CompositeAdvisorySource;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\Nvd\NvdAdvisorySource;
use mteu\AdvisoryMatcher\Source\Osv\OsvAdvisorySource;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Source\Packagist\PackagistAdvisorySource;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use mteu\AdvisoryMatcher\Tests\Unit\Advisory\AdvisoryBuilder;
use mteu\AdvisoryMatcher\Tests\Unit\Source\Http\RecordingHttpClient;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(AdvisoryBatch::class)]
#[CoversClass(PackagistAdvisorySource::class)]
#[CoversClass(OsvAdvisorySource::class)]
#[CoversClass(NvdAdvisorySource::class)]
#[CoversClass(CompositeAdvisorySource::class)]
final class FrameworkFreeContractTest extends TestCase
{
    #[Test]
    public function coverageIsAnswerableWithoutFetchingAnything(): void
    {
        $sources = $this->sources();

        $covered = [];
        foreach ($sources as $source) {
            foreach ($source->coveredEcosystems() as $ecosystem) {
                $covered[$ecosystem->value] = true;
            }
        }

        self::assertArrayHasKey('composer', $covered);
        self::assertArrayHasKey('npm', $covered);
        self::assertArrayNotHasKey('unknown', $covered);
    }

    #[Test]
    public function aFanOutOverTwoSourcesComposesWithNoContainer(): void
    {
        $composerPackage = new PackageRef(Ecosystem::Composer, 'vendor/one', '1.0.0');
        $npmPackage = new PackageRef(Ecosystem::Npm, 'lodash', '4.17.20');
        $uncoveredPackage = new PackageRef(Ecosystem::Unknown, 'requests', '2.31.0');

        $packages = [$composerPackage, $npmPackage, $uncoveredPackage];

        $batch = new AdvisoryBatch();
        foreach ($this->sources() as $source) {
            $batch = $batch->merge($source->advisoriesFor($packages));
        }

        self::assertTrue($batch->isComplete());

        self::assertTrue($batch->wasAnsweredFor($composerPackage));
        self::assertTrue($batch->wasAnsweredFor($npmPackage));

        self::assertCount(1, $batch->advisoriesFor($composerPackage));
        self::assertCount(1, $batch->advisoriesFor($npmPackage));

        // Neither answered for nor a failure: no configured source claims it,
        // so nobody was asked. Calling that clean is the bug this field exists
        // to prevent.
        self::assertFalse($batch->wasAnsweredFor($uncoveredPackage));
        self::assertSame([], $batch->advisoriesFor($uncoveredPackage));
    }

    #[Test]
    public function oneSourceFailingLeavesTheOtherSourcesCoverageIntact(): void
    {
        $composerPackage = new PackageRef(Ecosystem::Composer, 'vendor/one', '1.0.0');
        $npmPackage = new PackageRef(Ecosystem::Npm, 'lodash', '4.17.20');
        $packages = [$composerPackage, $npmPackage];

        $working = new StubAdvisorySource(
            'OSV',
            [Ecosystem::Npm],
            ['lodash' => [AdvisoryBuilder::build(advisoryId: 'OSV-GHSA-npm', packageName: 'lodash', ecosystem: Ecosystem::Npm)]],
        );
        $down = new StubAdvisorySource(
            'Packagist',
            [],
            [],
            [
                new SourceFailure(
                    sourceName: 'Packagist',
                    ecosystem: Ecosystem::Composer,
                    reason: FailureReason::Unreachable,
                    detail: 'connection refused',
                ),
            ],
        );

        $batch = $working->advisoriesFor($packages)->merge($down->advisoriesFor($packages));

        self::assertFalse($batch->isComplete());
        self::assertTrue($batch->wasAnsweredFor($npmPackage));
        self::assertFalse($batch->wasAnsweredFor($composerPackage));

        self::assertCount(1, $batch->failures);
        self::assertSame(Ecosystem::Composer, $batch->failures[0]->ecosystem);
        self::assertTrue($batch->failures[0]->reason->isTransient());
    }

    #[Test]
    public function aSourceIsOnlyAskedAboutWhatItIsGiven(): void
    {
        $packages = [new PackageRef(Ecosystem::Composer, 'vendor/one', '1.0.0')];

        $source = new StubAdvisorySource('Packagist', [Ecosystem::Composer]);
        $source->advisoriesFor($packages);

        self::assertSame($packages, $source->askedAbout());
    }

    #[Test]
    public function aRealSourceWiresFromAPsr18ClientAndNoContainer(): void
    {
        $factory = new Psr17Factory();
        $http = new RecordingHttpClient([
            new Response(200, [], (string)file_get_contents(__DIR__ . '/Packagist/Fixtures/monolog-psr-log-and-unknown.json')),
        ]);

        $source = new PackagistAdvisorySource($http, $factory, $factory);

        $package = new PackageRef(Ecosystem::Composer, 'monolog/monolog', '1.10.0');
        $batch = $source->advisoriesFor([$package]);

        self::assertTrue($batch->isComplete());
        self::assertTrue($batch->wasAnsweredFor($package));
        self::assertSame('PKSA-dmw8-jd8k-q3c6', $batch->advisoriesFor($package)[0]->advisoryId);
        self::assertCount(1, $http->sentRequests());
    }

    #[Test]
    public function twoRealSourcesWithOverlappingCoverageComposeWithNoContainer(): void
    {
        $factory = new Psr17Factory();
        $package = new PackageRef(Ecosystem::Composer, 'monolog/monolog', '1.10.0');

        $packagist = new PackagistAdvisorySource(new RecordingHttpClient([new Response(503)]), $factory, $factory);
        $osv = new OsvAdvisorySource(
            new RecordingHttpClient([
                new Response(200, [], '{"results": [{"vulns": [{"id": "GHSA-f2qw-2xgc-8c9x", "modified": "2024-01-01T00:00:00Z"}]}]}'),
                new Response(200, [], (string)json_encode([
                    'id' => 'GHSA-f2qw-2xgc-8c9x',
                    'affected' => [[
                        'package' => ['ecosystem' => 'Packagist', 'name' => 'monolog/monolog'],
                        'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '1.4.1'], ['fixed' => '1.12.0']]]],
                    ]],
                ])),
            ]),
            $factory,
            $factory,
        );

        self::assertContains(Ecosystem::Composer, $osv->coveredEcosystems());

        $batch = $packagist->advisoriesFor([$package]);
        $batch = $batch->merge($osv->advisoriesFor([$package]));

        self::assertFalse($batch->isComplete());
        self::assertSame('Packagist', $batch->failures[0]->sourceName);
        self::assertTrue($batch->wasAnsweredFor($package));
        self::assertSame('OSV-GHSA-f2qw-2xgc-8c9x', $batch->advisoriesFor($package)[0]->advisoryId);
    }

    #[Test]
    public function threeRealSourcesBehindOneCompositeWithPackagistDown(): void
    {
        $factory = new Psr17Factory();
        $monolog = new PackageRef(Ecosystem::Composer, 'monolog/monolog', '1.10.0');
        $php = new PackageRef(Ecosystem::Php, 'php', '8.3.14');

        $packagistHttp = new RecordingHttpClient([new Response(503)]);
        $osvHttp = new RecordingHttpClient([
            new Response(200, [], '{"results": [{"vulns": [{"id": "GHSA-f2qw-2xgc-8c9x", "modified": "2024-01-01T00:00:00Z"}]}]}'),
            new Response(200, [], (string)json_encode([
                'id' => 'GHSA-f2qw-2xgc-8c9x',
                'affected' => [[
                    'package' => ['ecosystem' => 'Packagist', 'name' => 'monolog/monolog'],
                    'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '1.4.1'], ['fixed' => '1.12.0']]]],
                ]],
            ])),
        ]);
        $nvdHttp = new RecordingHttpClient([
            new Response(200, [], (string)file_get_contents(__DIR__ . '/Nvd/Fixtures/cves-php-8.3.14.json')),
        ]);

        $composite = new CompositeAdvisorySource([
            new PackagistAdvisorySource($packagistHttp, $factory, $factory),
            new OsvAdvisorySource($osvHttp, $factory, $factory),
            new NvdAdvisorySource($nvdHttp, $factory),
        ]);

        $batch = $composite->advisoriesFor([$monolog, $php]);

        self::assertCount(1, $packagistHttp->sentRequests());
        self::assertCount(2, $osvHttp->sentRequests(), 'One querybatch and one record, not a second querybatch.');
        self::assertCount(1, $nvdHttp->sentRequests());

        self::assertFalse($batch->isComplete());
        self::assertSame(['Packagist'], array_map(
            static fn (SourceFailure $failure): string => $failure->sourceName,
            $batch->failures,
        ));

        self::assertTrue($batch->wasAnsweredFor($monolog));
        self::assertSame('OSV-GHSA-f2qw-2xgc-8c9x', $batch->advisoriesFor($monolog)[0]->advisoryId);
        self::assertTrue($batch->wasAnsweredFor($php));
        self::assertCount(2, $batch->advisoriesFor($php));
    }

    /**
     * @return list<AdvisorySource>
     */
    private function sources(): array
    {
        return [
            new StubAdvisorySource(
                'Packagist',
                [Ecosystem::Composer],
                ['vendor/one' => [AdvisoryBuilder::build(advisoryId: 'PKSA-one', packageName: 'vendor/one')]],
            ),
            new StubAdvisorySource(
                'OSV',
                [Ecosystem::Npm],
                ['lodash' => [AdvisoryBuilder::build(advisoryId: 'OSV-GHSA-npm', packageName: 'lodash', ecosystem: Ecosystem::Npm)]],
            ),
        ];
    }
}
