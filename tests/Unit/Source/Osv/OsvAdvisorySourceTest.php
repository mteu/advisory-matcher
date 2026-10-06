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

namespace mteu\AdvisoryMatcher\Tests\Unit\Source\Osv;

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\AdvisoryBatch;
use mteu\AdvisoryMatcher\Source\Cache\NullCache;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\Osv\OsvAdvisorySource;
use mteu\AdvisoryMatcher\Source\Osv\OsvApi;
use mteu\AdvisoryMatcher\Source\Osv\OsvCallFailure;
use mteu\AdvisoryMatcher\Source\Osv\OsvQuery;
use mteu\AdvisoryMatcher\Source\Osv\OsvVulnerabilityReference;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use mteu\AdvisoryMatcher\Tests\Unit\Clock\FrozenClock;
use mteu\AdvisoryMatcher\Tests\Unit\Source\Cache\SimpleCacheDouble;
use mteu\AdvisoryMatcher\Tests\Unit\Source\Http\EndlessStream;
use mteu\AdvisoryMatcher\Tests\Unit\Source\Http\NetworkFailure;
use mteu\AdvisoryMatcher\Tests\Unit\Source\Http\RecordingHttpClient;
use mteu\AdvisoryMatcher\Tests\Unit\Source\Http\ResettingStream;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\SimpleCache\CacheInterface;

#[CoversClass(OsvAdvisorySource::class)]
#[CoversClass(OsvApi::class)]
#[CoversClass(OsvCallFailure::class)]
#[CoversClass(OsvQuery::class)]
#[CoversClass(OsvVulnerabilityReference::class)]
final class OsvAdvisorySourceTest extends TestCase
{
    private const string LODASH_COMMAND_INJECTION = 'GHSA-35jh-r3h4-6jhm';

    private const string LODASH_REDOS = 'GHSA-29mw-wpgm-hmr9';

    #[Test]
    public function aHitIsHydratedAndFiledUnderTheAskedNameAndACleanPackageIsAnsweredToo(): void
    {
        $lodash = $this->npm('lodash');
        $express = $this->npm('express');

        $batch = $this->ask([$lodash, $express], [
            self::json(self::fixture('querybatch-lodash-hit-express-clean.json')),
            self::json(self::fixture(self::LODASH_COMMAND_INJECTION . '.json')),
            self::json(self::fixture(self::LODASH_REDOS . '.json')),
        ]);

        self::assertTrue($batch->isComplete());
        self::assertTrue($batch->wasAnsweredFor($lodash));
        self::assertTrue($batch->wasAnsweredFor($express), 'A package OSV names nothing for is answered and clean.');
        self::assertSame([], $batch->advisoriesFor($express));

        $advisories = $batch->advisoriesFor($lodash);
        self::assertCount(2, $advisories);
        self::assertSame(
            ['OSV-' . self::LODASH_COMMAND_INJECTION, 'OSV-' . self::LODASH_REDOS],
            array_map(static fn (Advisory $advisory): string => $advisory->advisoryId, $advisories),
        );
        self::assertSame('CVE-2021-23337', $advisories[0]->cve);
    }

    #[Test]
    public function onlyTheAffectedEntriesNamingTheAskedPackageShapeItsVersionRanges(): void
    {
        $batch = $this->ask([$this->npm('lodash')], [
            self::json(json_encode(['results' => [
                ['vulns' => [['id' => self::LODASH_COMMAND_INJECTION], ['id' => self::LODASH_REDOS]]],
            ]], JSON_THROW_ON_ERROR)),
            self::json(self::fixture(self::LODASH_COMMAND_INJECTION . '.json')),
            self::json(self::fixture(self::LODASH_REDOS . '.json')),
        ], 2);

        self::assertCount(2, $batch->advisories);
        self::assertSame('>=0,<4.17.21', $batch->advisories[0]->affectedVersions->toComposerConstraint());
        self::assertSame('>=4.0.0,<4.17.21 || >=0,<3.10.2', $batch->advisories[1]->affectedVersions->toComposerConstraint());
        self::assertSame('3.10.2', $batch->advisories[1]->firstPatchedVersion);
    }

    #[Test]
    public function theQueryNamesEachPackageOnceInOsvsOwnEcosystemLabelWithNoVersion(): void
    {
        $http = new RecordingHttpClient([self::json('{"results": [{}, {}]}')]);

        $this->subject($http)->advisoriesFor([
            new PackageRef(Ecosystem::Composer, 'monolog/monolog', '3.5.0'),
            new PackageRef(Ecosystem::Composer, 'monolog/monolog', '2.9.1'),
            new PackageRef(Ecosystem::Npm, 'lodash', '4.17.20'),
        ]);

        self::assertCount(1, $http->sentRequests());
        $request = $http->sentRequests()[0];
        self::assertSame('POST', $request->getMethod());
        self::assertSame('https://api.osv.dev/v1/querybatch', (string)$request->getUri());
        self::assertSame('application/json', $request->getHeaderLine('Content-Type'));
        self::assertSame(
            ['queries' => [
                ['package' => ['name' => 'monolog/monolog', 'ecosystem' => 'Packagist']],
                ['package' => ['name' => 'lodash', 'ecosystem' => 'npm']],
            ]],
            self::decodedBody($request),
        );
    }

    #[Test]
    public function twoVersionsOfOnePackageAreOneQueryAndBothAnswered(): void
    {
        $current = new PackageRef(Ecosystem::Npm, 'lodash', '4.17.21');
        $old = new PackageRef(Ecosystem::Npm, 'lodash', '3.10.1');

        $batch = $this->ask([$current, $old], [self::json('{"results": [{}]}')]);

        self::assertTrue($batch->wasAnsweredFor($current));
        self::assertTrue($batch->wasAnsweredFor($old));
    }

    #[Test]
    public function anEcosystemOsvDoesNotCoverIsNeitherAskedNorAFailure(): void
    {
        $http = new RecordingHttpClient();

        $batch = $this->subject($http)->advisoriesFor([
            new PackageRef(Ecosystem::Php, 'php', '8.4.1'),
            new PackageRef(Ecosystem::Unknown, 'zlib', '1.3'),
        ]);

        self::assertSame([], $http->sentRequests());
        self::assertSame([], $batch->answeredFor);
        self::assertSame([], $batch->failures);
    }

    #[Test]
    public function coverageIsTheRegistryEcosystemsAndNotThePhpRuntime(): void
    {
        $covered = $this->subject(new RecordingHttpClient())->coveredEcosystems();

        self::assertSame(
            [Ecosystem::Composer, Ecosystem::Npm],
            $covered,
        );
        self::assertSame('OSV', $this->subject(new RecordingHttpClient())->name());
    }

    #[Test]
    public function anEmptyAskSendsNothing(): void
    {
        $http = new RecordingHttpClient();

        $batch = $this->subject($http)->advisoriesFor([]);

        self::assertSame([], $http->sentRequests());
        self::assertTrue($batch->isComplete());
    }

    #[Test]
    public function aQueryOverTheBatchLimitIsChunkedAndAFailingChunkCostsOnlyItsOwnPackages(): void
    {
        $packages = array_map(fn (int $i): PackageRef => $this->npm('package-' . $i), range(1, 1001));
        $http = new RecordingHttpClient([
            self::json(json_encode(['results' => array_fill(0, 1000, new \stdClass())], JSON_THROW_ON_ERROR)),
            new Response(503),
        ]);

        $batch = $this->subject($http)->advisoriesFor($packages);

        self::assertCount(2, $http->sentRequests());
        self::assertCount(1000, self::decodedBody($http->sentRequests()[0])['queries']);
        self::assertCount(1, self::decodedBody($http->sentRequests()[1])['queries']);

        self::assertCount(1000, $batch->answeredFor);
        self::assertTrue($batch->wasAnsweredFor($packages[999]));
        self::assertFalse($batch->wasAnsweredFor($packages[1000]));

        self::assertCount(1, $batch->failures);
        self::assertSame(FailureReason::Unreachable, $batch->failures[0]->reason);
        self::assertSame(Ecosystem::Npm, $batch->failures[0]->ecosystem);
        self::assertSame('OSV', $batch->failures[0]->sourceName);
        self::assertStringStartsWith('1 package(s) left unanswered.', $batch->failures[0]->detail);
    }

    #[Test]
    public function aFailedChunkIsFiledUnderEveryEcosystemItCarried(): void
    {
        $batch = $this->ask(
            [$this->npm('lodash'), new PackageRef(Ecosystem::Composer, 'monolog/monolog', '3.5.0')],
            [new Response(429, ['Retry-After' => '30'])],
        );

        self::assertSame([], $batch->answeredFor);
        self::assertSame(
            [Ecosystem::Npm, Ecosystem::Composer],
            array_map(static fn (SourceFailure $failure): Ecosystem => $failure->ecosystem, $batch->failures),
        );

        foreach ($batch->failures as $failure) {
            self::assertSame(FailureReason::RateLimited, $failure->reason);
            self::assertSame(30, $failure->retryAfterSeconds);
        }
    }

    #[Test]
    public function aHitWhoseRecordCannotBeReadIsAFailureForThePackagesThatNamedItAndNoOthers(): void
    {
        $lodash = $this->npm('lodash');
        $underscore = $this->npm('underscore');

        $batch = $this->ask([$lodash, $underscore], [
            self::json(json_encode(['results' => [
                ['vulns' => [['id' => 'GHSA-gone', 'modified' => '2024-01-01T00:00:00Z'], ['id' => self::LODASH_REDOS, 'modified' => 'x']]],
                ['vulns' => [['id' => self::LODASH_REDOS, 'modified' => 'x']]],
            ]], JSON_THROW_ON_ERROR)),
            new Response(404),
            self::json(self::fixture(self::LODASH_REDOS . '.json')),
        ]);

        self::assertFalse($batch->wasAnsweredFor($lodash));
        self::assertSame([], $batch->advisoriesFor($lodash), 'Half an answer is not filed as a whole one.');

        self::assertTrue($batch->wasAnsweredFor($underscore));

        self::assertCount(1, $batch->failures);
        self::assertSame(FailureReason::Rejected, $batch->failures[0]->reason);
        self::assertSame(Ecosystem::Npm, $batch->failures[0]->ecosystem);
        self::assertStringContainsString('404', $batch->failures[0]->detail);
    }

    #[Test]
    public function onceOsvStopsAnsweringTheRemainingRecordsAreNotAskedFor(): void
    {
        $http = new RecordingHttpClient([
            self::json(json_encode(['results' => [
                ['vulns' => [['id' => 'GHSA-one'], ['id' => 'GHSA-two'], ['id' => 'GHSA-three']]],
            ]], JSON_THROW_ON_ERROR)),
            new NetworkFailure(new Request('GET', 'https://api.osv.dev/v1/vulns/GHSA-one'), 'Connection refused'),
        ]);

        $batch = $this->subject($http)->advisoriesFor([$this->npm('lodash')]);

        self::assertCount(2, $http->sentRequests(), 'One failed read is enough to know the rest will fail too.');
        self::assertSame(FailureReason::Unreachable, $batch->failures[0]->reason);
        self::assertSame([], $batch->answeredFor);
    }

    #[Test]
    public function aTimeoutIsToldApartFromARefusedConnection(): void
    {
        $batch = $this->ask([$this->npm('lodash')], [
            new NetworkFailure(new Request('POST', 'https://api.osv.dev/v1/querybatch'), 'Operation timed out after 10001 milliseconds'),
        ]);

        self::assertSame(FailureReason::Timeout, $batch->failures[0]->reason);
    }

    #[Test]
    public function aRecordIsReadFromTheRecordCacheWhileItsModifiedTimestampHolds(): void
    {
        $cache = new SimpleCacheDouble();
        $querybatch = '{"results": [{"vulns": [{"id": "' . self::LODASH_REDOS . '", "modified": "2023-11-08T04:05:37.113Z"}]}]}';

        $first = new RecordingHttpClient([self::json($querybatch), self::json(self::fixture(self::LODASH_REDOS . '.json'))]);
        $this->subject($first, $cache)->advisoriesFor([$this->npm('lodash')]);

        $second = new RecordingHttpClient([self::json($querybatch)]);
        $batch = $this->subject($second, $cache)->advisoriesFor([$this->npm('underscore')]);

        self::assertCount(1, $second->sentRequests(), 'Only the querybatch goes out; the record is already known.');
        self::assertCount(1, $batch->advisories);
        self::assertSame('underscore', $batch->advisories[0]->packageName);

        $keys = $cache->storedKeys();
        self::assertCount(1, $keys);
        self::assertMatchesRegularExpression('/^record_v1_[0-9a-f]{40}$/', $keys[0]);
        self::assertSame(7 * 24 * 60 * 60, $cache->ttlOf($keys[0]));
    }

    #[Test]
    public function anUpstreamEditToARecordIsFetchedAgainRatherThanServedFromTheCache(): void
    {
        $cache = new SimpleCacheDouble();

        $this->subject(new RecordingHttpClient([
            self::json('{"results": [{"vulns": [{"id": "' . self::LODASH_REDOS . '", "modified": "2023-11-08T04:05:37.113Z"}]}]}'),
            self::json(self::fixture(self::LODASH_REDOS . '.json')),
        ]), $cache)->advisoriesFor([$this->npm('lodash')]);

        $edited = new RecordingHttpClient([
            self::json('{"results": [{"vulns": [{"id": "' . self::LODASH_REDOS . '", "modified": "2025-01-01T00:00:00Z"}]}]}'),
            self::json(self::fixture(self::LODASH_REDOS . '.json')),
        ]);
        $this->subject($edited, $cache)->advisoriesFor([$this->npm('lodash')]);

        self::assertCount(2, $edited->sentRequests());
        self::assertSame(
            'https://api.osv.dev/v1/vulns/' . self::LODASH_REDOS,
            (string)$edited->sentRequests()[1]->getUri(),
        );
    }

    #[Test]
    public function aCachedEntryThatIsNotThisRecordIsNotTrusted(): void
    {
        $cache = new SimpleCacheDouble();
        $modified = '2023-11-08T04:05:37.113Z';
        $cache->set('record_v1_' . sha1(self::LODASH_REDOS . "\0" . $modified), ['id' => 'GHSA-someone-else']);

        $http = new RecordingHttpClient([
            self::json('{"results": [{"vulns": [{"id": "' . self::LODASH_REDOS . '", "modified": "' . $modified . '"}]}]}'),
            self::json(self::fixture(self::LODASH_REDOS . '.json')),
        ]);
        $batch = $this->subject($http, $cache)->advisoriesFor([$this->npm('lodash')]);

        self::assertCount(2, $http->sentRequests());
        self::assertSame('OSV-' . self::LODASH_REDOS, $batch->advisories[0]->advisoryId);
    }

    #[Test]
    public function withoutARecordCacheEveryRunReadsTheRecordAgain(): void
    {
        $querybatch = '{"results": [{"vulns": [{"id": "' . self::LODASH_REDOS . '", "modified": "x"}]}]}';
        $http = new RecordingHttpClient([
            self::json($querybatch),
            self::json(self::fixture(self::LODASH_REDOS . '.json')),
            self::json($querybatch),
            self::json(self::fixture(self::LODASH_REDOS . '.json')),
        ]);

        $source = $this->subject($http, new NullCache());
        $source->advisoriesFor([$this->npm('lodash')]);
        $source->advisoriesFor([$this->npm('lodash')]);

        self::assertCount(4, $http->sentRequests());
    }

    #[Test]
    public function aPagedResultIsFollowedForTheQueriesStillPagingOnly(): void
    {
        $lodash = $this->npm('lodash');
        $express = $this->npm('express');
        $http = new RecordingHttpClient([
            self::json('{"results": [{"vulns": [{"id": "GHSA-a"}], "next_page_token": "page-2"}, {}]}'),
            self::json('{"results": [{"vulns": [{"id": "GHSA-b"}]}]}'),
            self::json('{"id": "GHSA-a"}'),
            self::json('{"id": "GHSA-b"}'),
        ]);

        $batch = $this->subject($http)->advisoriesFor([$lodash, $express]);

        self::assertSame(
            ['queries' => [['package' => ['name' => 'lodash', 'ecosystem' => 'npm'], 'page_token' => 'page-2']]],
            self::decodedBody($http->sentRequests()[1]),
        );
        self::assertCount(2, $batch->advisoriesFor($lodash));
        self::assertTrue($batch->wasAnsweredFor($express));
    }

    #[Test]
    public function aFeedThatNeverStopsPagingIsAFailureRatherThanAnEndlessLoop(): void
    {
        $http = new RecordingHttpClient(array_map(
            static fn (): ResponseInterface => self::json('{"results": [{"next_page_token": "again"}]}'),
            range(1, 10),
        ));

        $batch = $this->subject($http)->advisoriesFor([$this->npm('lodash')]);

        self::assertCount(10, $http->sentRequests());
        self::assertSame(FailureReason::Unparseable, $batch->failures[0]->reason);
        self::assertSame([], $batch->answeredFor);
    }

    /**
     * @return \Generator<string, array{string}>
     */
    public static function querybatchBodiesThatAreNotTheDocumentedShape(): \Generator
    {
        yield 'not JSON' => ['<html>Service Unavailable</html>'];
        yield 'empty body' => [''];
        yield 'a JSON scalar' => ['"results"'];
        yield 'a JSON list' => ['[{}]'];
        yield 'no results' => ['{"error": "bad request"}'];
        yield 'results as a map' => ['{"results": {"lodash": {}}}'];
        yield 'fewer results than queries' => ['{"results": []}'];
        yield 'a result that is not an object' => ['{"results": ["lodash"]}'];
        yield 'vulns that are not a list' => ['{"results": [{"vulns": {"id": "GHSA-a"}}]}'];
        yield 'a reference without an id' => ['{"results": [{"vulns": [{"modified": "2024-01-01T00:00:00Z"}]}]}'];
        yield 'a reference with a blank id' => ['{"results": [{"vulns": [{"id": " "}]}]}'];
        yield 'a reference whose id is a path' => ['{"results": [{"vulns": [{"id": "../querybatch"}]}]}'];
    }

    #[Test]
    #[DataProvider('querybatchBodiesThatAreNotTheDocumentedShape')]
    public function aQuerybatchBodyThatIsNotTheDocumentedShapeIsUnparseableRatherThanClean(string $body): void
    {
        $package = $this->npm('lodash');

        $batch = $this->ask([$package], [self::json($body)]);

        self::assertCount(1, $batch->failures);
        self::assertSame(FailureReason::Unparseable, $batch->failures[0]->reason);
        self::assertFalse($batch->wasAnsweredFor($package));
    }

    /**
     * @return \Generator<string, array{string}>
     */
    public static function recordBodiesThatAreNotARecord(): \Generator
    {
        yield 'not JSON' => ['{"id": "GHSA-a", '];
        yield 'no id' => ['{"summary": "lost its id"}'];
        yield 'a blank id' => ['{"id": ""}'];
    }

    #[Test]
    #[DataProvider('recordBodiesThatAreNotARecord')]
    public function aRecordBodyThatIsNotARecordIsAFailureForItsPackage(string $body): void
    {
        $package = $this->npm('lodash');

        $batch = $this->ask([$package], [
            self::json('{"results": [{"vulns": [{"id": "GHSA-a"}]}]}'),
            self::json($body),
        ]);

        self::assertSame(FailureReason::Unparseable, $batch->failures[0]->reason);
        self::assertFalse($batch->wasAnsweredFor($package));
        self::assertSame([], $batch->advisories);
    }

    #[Test]
    public function aBodyOverTheSizeGuardIsRefusedWithoutBeingFullyBuffered(): void
    {
        $body = new EndlessStream();

        $batch = $this->ask([$this->npm('lodash')], [(new Response(200))->withBody($body)]);

        self::assertSame(FailureReason::Unparseable, $batch->failures[0]->reason);
        self::assertStringContainsString('25 MiB', $batch->failures[0]->detail);
        self::assertLessThan(500, $body->reads());
    }

    #[Test]
    public function aBodyThatBreaksOffMidReadIsAnUnreachableFeedRatherThanAThrow(): void
    {
        $package = $this->npm('lodash');

        $batch = $this->ask([$package], [(new Response(200))->withBody(new ResettingStream())]);

        self::assertCount(1, $batch->failures);
        self::assertSame(FailureReason::Unreachable, $batch->failures[0]->reason);
        self::assertStringContainsString('Connection reset by peer', $batch->failures[0]->detail);
        self::assertFalse($batch->wasAnsweredFor($package));
    }

    #[Test]
    public function aRecordWhoseBodyBreaksOffStopsTheRemainingRecordReads(): void
    {
        $package = $this->npm('lodash');

        $batch = $this->ask(
            [$package],
            [
                self::json('{"results": [{"vulns": [{"id": "GHSA-a"}, {"id": "GHSA-b"}]}]}'),
                (new Response(200))->withBody(new ResettingStream('Operation timed out after 30000 milliseconds')),
            ],
            expectedRequests: 1,
        );

        self::assertSame(FailureReason::Timeout, $batch->failures[0]->reason);
        self::assertFalse($batch->wasAnsweredFor($package));
    }

    #[Test]
    public function aNameThatIsNotValidUtf8IsRefusedRatherThanAskedAboutUnderAnotherName(): void
    {
        $broken = $this->npm("lod\xC3\x28sh");
        $http = new RecordingHttpClient([self::json('{"results": [{}]}')]);

        $batch = $this->subject($http)->advisoriesFor([$broken, $this->npm('express')]);

        self::assertCount(1, self::decodedBody($http->sentRequests()[0])['queries']);
        self::assertFalse($batch->wasAnsweredFor($broken));
        self::assertSame(FailureReason::Rejected, $batch->failures[0]->reason);
    }

    #[Test]
    public function aRecordWithoutADateIsDatedByTheClockTheConsumerPasses(): void
    {
        $http = new RecordingHttpClient([
            self::json('{"results": [{"vulns": [{"id": "GHSA-a"}]}]}'),
            self::json((string)json_encode([
                'id' => 'GHSA-a',
                'affected' => [[
                    'package' => ['ecosystem' => 'npm', 'name' => 'lodash'],
                    'ranges' => [['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '4.17.21']]]],
                ]],
            ])),
        ]);
        $factory = new Psr17Factory();
        $package = $this->npm('lodash');

        $source = new OsvAdvisorySource($http, $factory, $factory, clock: FrozenClock::at('2020-02-02T00:00:00+00:00'));

        self::assertEquals(
            new \DateTimeImmutable('2020-02-02T00:00:00+00:00'),
            $source->advisoriesFor([$package])->advisoriesFor($package)[0]->reportedAt,
        );
    }

    #[Test]
    public function sendsRequestsToTheEndpointTheConsumerConfigured(): void
    {
        $http = new RecordingHttpClient([self::json('{"results": [{"vulns": [{"id": "GHSA-a"}]}]}'), self::json('{"id": "GHSA-a"}')]);
        $factory = new Psr17Factory();

        (new OsvAdvisorySource(
            httpClient: $http,
            requestFactory: $factory,
            streamFactory: $factory,
            clock: FrozenClock::at('2026-09-24T12:00:00+00:00'),
            endpoint: 'https://osv.mirror.example/v1/',
        ))->advisoriesFor([$this->npm('lodash')]);

        self::assertSame('https://osv.mirror.example/v1/querybatch', (string)$http->sentRequests()[0]->getUri());
        self::assertSame('https://osv.mirror.example/v1/vulns/GHSA-a', (string)$http->sentRequests()[1]->getUri());
    }

    #[Test]
    public function theQueryAndEveryRecordReadCarryTheUserAgent(): void
    {
        $http = new RecordingHttpClient([self::json('{"results": [{"vulns": [{"id": "GHSA-a"}]}]}'), self::json('{"id": "GHSA-a"}')]);
        $factory = new Psr17Factory();

        (new OsvAdvisorySource($http, $factory, $factory, userAgent: 'acme-monitor/2.1 (+https://acme.example/contact)'))
            ->advisoriesFor([$this->npm('lodash')]);

        self::assertCount(2, $http->sentRequests());
        foreach ($http->sentRequests() as $request) {
            self::assertSame('acme-monitor/2.1 (+https://acme.example/contact)', $request->getHeaderLine('User-Agent'));
        }
    }

    #[Test]
    public function withoutAUserAgentOptionTheLibraryNamesItself(): void
    {
        $http = new RecordingHttpClient([self::json('{"results": [{}]}')]);

        $this->subject($http)->advisoriesFor([$this->npm('lodash')]);

        self::assertSame(
            'mteu/advisory-matcher (+https://github.com/mteu/advisory-matcher)',
            $http->sentRequests()[0]->getHeaderLine('User-Agent'),
        );
    }

    /**
     * @param list<PackageRef> $packages
     * @param list<ResponseInterface|ClientExceptionInterface> $answers
     */
    private function ask(array $packages, array $answers, int $expectedRequests = -1): AdvisoryBatch
    {
        $http = new RecordingHttpClient($answers);
        $batch = $this->subject($http)->advisoriesFor($packages);

        if ($expectedRequests >= 0) {
            self::assertCount($expectedRequests + 1, $http->sentRequests());
        }

        return $batch;
    }

    private function subject(RecordingHttpClient $http, CacheInterface $recordCache = new NullCache()): OsvAdvisorySource
    {
        $factory = new Psr17Factory();

        return new OsvAdvisorySource(
            httpClient: $http,
            requestFactory: $factory,
            streamFactory: $factory,
            clock: FrozenClock::at('2026-09-24T12:00:00+00:00'),
            recordCache: $recordCache,
        );
    }

    private function npm(string $name): PackageRef
    {
        return new PackageRef(Ecosystem::Npm, $name, '1.0.0');
    }

    private static function json(string $body): ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'application/json'], $body);
    }

    private static function fixture(string $name): string
    {
        $contents = file_get_contents(__DIR__ . '/Fixtures/' . $name);
        self::assertIsString($contents);

        return $contents;
    }

    /**
     * @return array{queries: list<mixed>}
     */
    private static function decodedBody(RequestInterface $request): array
    {
        /** @var array{queries: list<mixed>} $decoded */
        $decoded = json_decode((string)$request->getBody(), true, 512, JSON_THROW_ON_ERROR);

        return $decoded;
    }
}
