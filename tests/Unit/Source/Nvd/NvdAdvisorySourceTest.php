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

namespace mteu\AdvisoryMatcher\Tests\Unit\Source\Nvd;

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Source\AdvisoryBatch;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\Nvd\NvdAdvisorySource;
use mteu\AdvisoryMatcher\Source\Nvd\NvdApi;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Tests\Unit\Clock\FrozenClock;
use mteu\AdvisoryMatcher\Tests\Unit\Source\Http\CollectingLogger;
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

#[CoversClass(NvdAdvisorySource::class)]
#[CoversClass(NvdApi::class)]
final class NvdAdvisorySourceTest extends TestCase
{
    private const string API_KEY = 'nvd-secret-key-0123';

    private const string CPE_8_3_14 = 'cpe:2.3:a:php:php:8.3.14:*:*:*:*:*:*:*';

    #[Test]
    public function aComponentsCvesAreFiledUnderTheAskedNameAndTheComponentIsAnswered(): void
    {
        $php = $this->php('8.3.14');

        $batch = $this->ask([$php], [self::json(self::fixture('cves-php-8.3.14.json'))]);

        self::assertTrue($batch->isComplete());
        self::assertTrue($batch->wasAnsweredFor($php));
        self::assertSame(
            ['NVD-CVE-2025-1217', 'NVD-CVE-2024-11235'],
            array_map(static fn (Advisory $advisory): string => $advisory->advisoryId, $batch->advisoriesFor($php)),
            'The withdrawn record is left out.',
        );
        self::assertSame('php', $batch->advisories[0]->packageName);
        self::assertSame(Severity::High, $batch->advisories[0]->severity);
        self::assertSame(Severity::Critical, $batch->advisories[1]->severity);
    }

    #[Test]
    public function nvdIsAskedByCpeAtTheInstalledVersionForVulnerableUnrejectedRecords(): void
    {
        $http = new RecordingHttpClient([self::json(self::emptyPage())]);

        $this->subject($http)->advisoriesFor([$this->php('8.3.14')]);

        self::assertCount(1, $http->sentRequests());
        $request = $http->sentRequests()[0];
        self::assertSame('GET', $request->getMethod());
        self::assertSame('services.nvd.nist.gov', $request->getUri()->getHost());
        self::assertSame('/rest/json/cves/2.0', $request->getUri()->getPath());
        self::assertSame('application/json', $request->getHeaderLine('Accept'));
        self::assertSame(
            'cpeName=cpe%3A2.3%3Aa%3Aphp%3Aphp%3A8.3.14%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A'
            . '&isVulnerable=&noRejected=&resultsPerPage=2000&startIndex=0',
            $request->getUri()->getQuery(),
        );
        self::assertSame(self::CPE_8_3_14, self::query($request)['cpeName'] ?? null);
    }

    #[Test]
    public function aDistributionVersionIsAskedAboutAsItsUpstreamRelease(): void
    {
        $http = new RecordingHttpClient([self::json(self::fixture('cves-php-8.3.14.json'))]);

        $batch = $this->subject($http)->advisoriesFor([$this->php('8.3.14-1~deb12u1')]);

        self::assertSame(self::CPE_8_3_14, self::query($http->sentRequests()[0])['cpeName'] ?? null);
        self::assertSame('8.3.19', $batch->advisories[0]->firstPatchedVersion);
    }

    #[Test]
    public function theApiKeyIsTheArgumentAfterThePsrCollaborators(): void
    {
        $http = new RecordingHttpClient([self::json(self::emptyPage())]);

        (new NvdAdvisorySource($http, new Psr17Factory(), self::API_KEY))->advisoriesFor([$this->php('8.3.14')]);

        self::assertSame(self::API_KEY, $http->sentRequests()[0]->getHeaderLine('apiKey'));
    }

    #[Test]
    public function theRequestCarriesTheUserAgent(): void
    {
        $http = new RecordingHttpClient([self::json(self::emptyPage()), self::json(self::emptyPage())]);
        $factory = new Psr17Factory();

        (new NvdAdvisorySource($http, $factory))->advisoriesFor([$this->php('8.3.14')]);
        (new NvdAdvisorySource($http, $factory, userAgent: 'acme-monitor/2.1 (+https://acme.example/contact)'))
            ->advisoriesFor([$this->php('8.3.14')]);

        self::assertSame(
            'mteu/advisory-matcher (+https://github.com/mteu/advisory-matcher)',
            $http->sentRequests()[0]->getHeaderLine('User-Agent'),
        );
        self::assertSame('acme-monitor/2.1 (+https://acme.example/contact)', $http->sentRequests()[1]->getHeaderLine('User-Agent'));
    }

    #[Test]
    public function aRecordWithoutADateIsDatedByTheClockTheConsumerPasses(): void
    {
        $http = new RecordingHttpClient([self::json((string)json_encode([
            'resultsPerPage' => 1,
            'startIndex' => 0,
            'totalResults' => 1,
            'format' => 'NVD_CVE',
            'version' => '2.0',
            'vulnerabilities' => [['cve' => ['id' => 'CVE-2025-0001', 'vulnStatus' => 'Analyzed']]],
        ]))]);
        $php = $this->php('8.3.14');

        $source = new NvdAdvisorySource($http, new Psr17Factory(), clock: FrozenClock::at('2020-02-02T00:00:00+00:00'));

        self::assertEquals(
            new \DateTimeImmutable('2020-02-02T00:00:00+00:00'),
            $source->advisoriesFor([$php])->advisoriesFor($php)[0]->reportedAt,
        );
    }

    #[Test]
    public function theApiKeyTravelsInAHeaderAndNeverInTheQueryString(): void
    {
        $http = new RecordingHttpClient([self::json(self::emptyPage())]);

        $this->subject($http, ' ' . self::API_KEY . ' ')->advisoriesFor([$this->php('8.3.14')]);

        $request = $http->sentRequests()[0];
        self::assertSame(self::API_KEY, $request->getHeaderLine('apiKey'));
        self::assertStringNotContainsString(self::API_KEY, (string)$request->getUri());
    }

    #[Test]
    #[DataProvider('absentKeyProvider')]
    public function withoutAKeyNoKeyHeaderIsSent(string $apiKey): void
    {
        $http = new RecordingHttpClient([self::json(self::emptyPage())]);

        $this->subject($http, $apiKey)->advisoriesFor([$this->php('8.3.14')]);

        self::assertFalse($http->sentRequests()[0]->hasHeader('apiKey'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function absentKeyProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'whitespace' => ['   '];
    }

    #[Test]
    public function aCleanComponentIsAnsweredWithNothingFound(): void
    {
        $php = $this->php('8.4.12');

        $batch = $this->ask([$php], [self::json(self::emptyPage())]);

        self::assertTrue($batch->wasAnsweredFor($php));
        self::assertSame([], $batch->advisories);
        self::assertSame([], $batch->failures);
    }

    #[Test]
    public function aComponentWithoutADerivableCpeIsNeitherAskedNorAnsweredNorAFailure(): void
    {
        $http = new RecordingHttpClient();
        $fpm = $this->php('8.3.14', 'php-fpm');
        $unknownVersion = $this->php('unknown');

        $batch = $this->subject($http)->advisoriesFor([$fpm, $unknownVersion]);

        self::assertSame([], $http->sentRequests());
        self::assertFalse($batch->wasAnsweredFor($fpm));
        self::assertFalse($batch->wasAnsweredFor($unknownVersion));
        self::assertSame([], $batch->failures);
    }

    #[Test]
    public function anEcosystemNvdDoesNotCoverIsNeitherAskedNorAFailure(): void
    {
        $http = new RecordingHttpClient();

        $batch = $this->subject($http)->advisoriesFor([
            new PackageRef(PackageUrl::fromPackageName('composer', 'php'), '8.3.14'),
            new PackageRef(PackageUrl::fromPackageName('npm', 'lodash'), '4.17.21'),
        ]);

        self::assertSame([], $http->sentRequests());
        self::assertSame([], $batch->answeredFor);
        self::assertSame([], $batch->failures);
    }

    #[Test]
    public function coverageIsThePhpRuntimeAlone(): void
    {
        $source = $this->subject(new RecordingHttpClient());

        self::assertSame([Ecosystem::Php], $source->coveredEcosystems());
        self::assertSame('NVD', $source->name());
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
    public function oneComponentAskedForTwiceAtOneReleaseIsAskedOnce(): void
    {
        $php = $this->php('8.3.14');
        $http = new RecordingHttpClient([self::json(self::fixture('cves-php-8.3.14.json'))]);

        $batch = $this->subject($http)->advisoriesFor([$php, $php]);

        self::assertCount(1, $http->sentRequests());
        self::assertTrue($batch->wasAnsweredFor($php));
        self::assertCount(2, $batch->advisoriesFor($php));
    }

    #[Test]
    public function anAnswerSpanningSeveralPagesIsFollowedToItsEnd(): void
    {
        $http = new RecordingHttpClient([
            self::json(self::page(2001, 'CVE-2025-1217')),
            self::json(self::page(2001, 'CVE-2025-1219')),
        ]);

        $batch = $this->subject($http)->advisoriesFor([$this->php('8.3.14')]);

        self::assertCount(2, $http->sentRequests());
        self::assertSame('2000', self::query($http->sentRequests()[1])['startIndex'] ?? null);
        self::assertSame(
            ['NVD-CVE-2025-1217', 'NVD-CVE-2025-1219'],
            array_map(static fn (Advisory $advisory): string => $advisory->advisoryId, $batch->advisories),
        );
        self::assertTrue($batch->isComplete());
    }

    #[Test]
    public function aWalkStillPagingAtThePageCapIsAFailureRatherThanAPartialAnswer(): void
    {
        $php = $this->php('8.3.14');
        $http = new RecordingHttpClient(array_map(
            static fn (int $page): ResponseInterface => self::json(self::page(12000, 'CVE-2025-' . (1000 + $page))),
            range(1, 5),
        ));

        $batch = $this->subject($http)->advisoriesFor([$php]);

        self::assertCount(5, $http->sentRequests());
        self::assertFalse($batch->wasAnsweredFor($php));
        self::assertSame([], $batch->advisories);
        self::assertCount(1, $batch->failures);
        self::assertSame(FailureReason::Unparseable, $batch->failures[0]->reason);
        self::assertStringContainsString('still paging after 5 pages', $batch->failures[0]->detail);
    }

    #[Test]
    #[DataProvider('forbiddenProvider')]
    public function a403IsARejectionWhoseDetailCarriesNoCredentialAndNoQuery(string $apiKey): void
    {
        $logger = new CollectingLogger();
        $php = $this->php('8.3.14');
        $http = new RecordingHttpClient([new Response(403, [], 'Forbidden')]);

        $batch = $this->subject($http, $apiKey, $logger)->advisoriesFor([$php]);

        self::assertFalse($batch->wasAnsweredFor($php));
        self::assertCount(1, $batch->failures);

        $failure = $batch->failures[0];
        self::assertSame('NVD', $failure->sourceName);
        self::assertSame(Ecosystem::Php, $failure->ecosystem);
        self::assertSame(FailureReason::Rejected, $failure->reason);
        self::assertNull($failure->retryAfterSeconds);
        self::assertSame(
            '1 component(s) left unanswered. NVD answered 403 to GET /rest/json/cves/2.0.',
            $failure->detail,
        );
        self::assertStringNotContainsString(self::API_KEY, $logger->transcript());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function forbiddenProvider(): iterable
    {
        yield 'no key' => [''];
        yield 'a bad key' => [self::API_KEY];
    }

    #[Test]
    public function a429IsRateLimitedCarriesRetryAfterAndStopsTheRemainingAsks(): void
    {
        $php = $this->php('8.3.14');
        $older = $this->php('8.2.20');
        $http = new RecordingHttpClient([new Response(429, ['Retry-After' => '30'])]);

        $batch = $this->subject($http)->advisoriesFor([$php, $older]);

        self::assertCount(1, $http->sentRequests());
        self::assertSame([], $batch->answeredFor);
        self::assertCount(1, $batch->failures);
        self::assertSame(FailureReason::RateLimited, $batch->failures[0]->reason);
        self::assertSame(30, $batch->failures[0]->retryAfterSeconds);
        self::assertStringStartsWith('2 component(s) left unanswered.', $batch->failures[0]->detail);
    }

    #[Test]
    public function aRejectionCostsOnlyItsOwnComponent(): void
    {
        $php = $this->php('8.3.14');
        $older = $this->php('8.2.20');
        $http = new RecordingHttpClient([new Response(404), self::json(self::emptyPage())]);

        $batch = $this->subject($http)->advisoriesFor([$php, $older]);

        self::assertCount(2, $http->sentRequests());
        self::assertFalse($batch->wasAnsweredFor($php));
        self::assertTrue($batch->wasAnsweredFor($older));
        self::assertSame(FailureReason::Rejected, $batch->failures[0]->reason);
    }

    #[Test]
    public function aServerErrorIsUnreachable(): void
    {
        $batch = $this->ask([$this->php('8.3.14')], [new Response(503, [], 'Service Unavailable, not JSON')]);

        self::assertSame(FailureReason::Unreachable, $batch->failures[0]->reason);
    }

    #[Test]
    #[DataProvider('malformedBodyProvider')]
    public function aBodyNotInTheDocumentedShapeIsUnparseableRatherThanClean(string $body): void
    {
        $php = $this->php('8.3.14');

        $batch = $this->ask([$php], [self::json($body)]);

        self::assertFalse($batch->wasAnsweredFor($php));
        self::assertSame(FailureReason::Unparseable, $batch->failures[0]->reason);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedBodyProvider(): iterable
    {
        yield 'no vulnerabilities list' => ['{"resultsPerPage": 0, "totalResults": 0}'];
        yield 'no total' => ['{"vulnerabilities": []}'];
        yield 'vulnerabilities is an object' => ['{"vulnerabilities": {"a": 1}, "totalResults": 1}'];
        yield 'an entry without a cve' => ['{"vulnerabilities": [{"id": "CVE-2025-1217"}], "totalResults": 1}'];
        yield 'not JSON' => ['<html>Service Unavailable</html>'];
        yield 'a JSON list' => ['[1, 2]'];
    }

    #[Test]
    public function anOversizedResponseIsRefusedBeforeItIsRead(): void
    {
        $batch = $this->ask([$this->php('8.3.14')], [
            new Response(200, ['Content-Length' => (string)(26 * 1024 * 1024)], self::emptyPage()),
        ]);

        self::assertSame(FailureReason::Unparseable, $batch->failures[0]->reason);
        self::assertStringContainsString('25 MiB', $batch->failures[0]->detail);
    }

    #[Test]
    public function aTimeoutIsToldApartFromARefusedConnection(): void
    {
        $request = new Request('GET', 'https://services.nvd.nist.gov/rest/json/cves/2.0');

        $timedOut = $this->ask([$this->php('8.3.14')], [new NetworkFailure($request, 'Operation timed out after 20001 milliseconds')]);
        $refused = $this->ask([$this->php('8.3.14')], [new NetworkFailure($request, 'Connection refused')]);

        self::assertSame(FailureReason::Timeout, $timedOut->failures[0]->reason);
        self::assertSame(FailureReason::Unreachable, $refused->failures[0]->reason);
    }

    #[Test]
    public function aTransportFailureIsLoggedWithoutTheRequestThatCarriesTheKey(): void
    {
        $logger = new CollectingLogger();
        $request = (new Request('GET', 'https://services.nvd.nist.gov/rest/json/cves/2.0'))
            ->withHeader('apiKey', self::API_KEY);
        $http = new RecordingHttpClient([new NetworkFailure($request, 'Connection refused')]);

        $batch = $this->subject($http, self::API_KEY, $logger)->advisoriesFor([$this->php('8.3.14')]);

        self::assertCount(1, $logger->records());
        self::assertSame(['message' => 'Connection refused'], $logger->records()[0]['context']);
        self::assertStringNotContainsString(self::API_KEY, $logger->transcript());
        self::assertStringNotContainsString(self::API_KEY, $batch->failures[0]->detail);
    }

    #[Test]
    public function aBodyThatBreaksOffMidReadIsAnUnreachableFeedLoggedByMessageOnly(): void
    {
        $logger = new CollectingLogger();
        $package = $this->php('8.3.14');
        $http = new RecordingHttpClient([(new Response(200))->withBody(new ResettingStream())]);

        $batch = $this->subject($http, self::API_KEY, $logger)->advisoriesFor([$package]);

        self::assertCount(1, $batch->failures);
        self::assertSame(FailureReason::Unreachable, $batch->failures[0]->reason);
        self::assertFalse($batch->wasAnsweredFor($package));
        self::assertCount(1, $logger->records());
        self::assertSame(
            ['message' => 'The response body could not be read: Connection reset by peer'],
            $logger->records()[0]['context'],
        );
    }

    /**
     * @param list<PackageRef> $packages
     * @param list<ResponseInterface|ClientExceptionInterface> $answers
     */
    private function ask(array $packages, array $answers): AdvisoryBatch
    {
        return $this->subject(new RecordingHttpClient($answers))->advisoriesFor($packages);
    }

    private function subject(
        RecordingHttpClient $http,
        string $apiKey = '',
        CollectingLogger $logger = new CollectingLogger(),
    ): NvdAdvisorySource {
        return new NvdAdvisorySource(
            httpClient: $http,
            requestFactory: new Psr17Factory(),
            apiKey: $apiKey,
            logger: $logger,
            clock: FrozenClock::at('2026-09-24T12:00:00+00:00'),
        );
    }

    private function php(string $version, string $name = 'php'): PackageRef
    {
        return new PackageRef(PackageUrl::fromPackageName('generic', $name), $version);
    }

    /**
     * @return array<string, mixed>
     */
    private static function query(RequestInterface $request): array
    {
        parse_str($request->getUri()->getQuery(), $query);

        $typed = [];

        foreach ($query as $key => $value) {
            $typed[(string)$key] = $value;
        }

        return $typed;
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

    private static function emptyPage(): string
    {
        return '{"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "format": "NVD_CVE", "version": "2.0", "vulnerabilities": []}';
    }

    private static function page(int $totalResults, string $cveId): string
    {
        return json_encode([
            'resultsPerPage' => 1,
            'startIndex' => 0,
            'totalResults' => $totalResults,
            'format' => 'NVD_CVE',
            'version' => '2.0',
            'vulnerabilities' => [[
                'cve' => [
                    'id' => $cveId,
                    'vulnStatus' => 'Analyzed',
                    'published' => '2025-03-29T06:15:36.557',
                    'descriptions' => [['lang' => 'en', 'value' => 'A flaw in the http request module.']],
                ],
            ]],
        ], JSON_THROW_ON_ERROR);
    }
}
