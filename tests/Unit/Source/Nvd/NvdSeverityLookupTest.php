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

use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\Nvd\NvdApi;
use mteu\AdvisoryMatcher\Source\Nvd\NvdSeverityLookup;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use mteu\AdvisoryMatcher\Tests\Unit\Source\Http\CollectingLogger;
use mteu\AdvisoryMatcher\Tests\Unit\Source\Http\RecordingHttpClient;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

#[CoversClass(NvdSeverityLookup::class)]
#[CoversClass(NvdApi::class)]
final class NvdSeverityLookupTest extends TestCase
{
    private const string API_KEY = 'nvd-secret-key-0123';

    private const string CVE = 'CVE-2026-109162';

    #[Test]
    public function theSeverityIsReadFromTheCveRecord(): void
    {
        $http = new RecordingHttpClient([self::json(self::recordWith(self::CVE, [
            'cvssMetricV31' => [['type' => 'Primary', 'cvssData' => ['baseScore' => 9.1, 'baseSeverity' => 'CRITICAL']]],
        ]))]);

        self::assertSame(Severity::Critical, $this->subject($http)->severityForCve(self::CVE));
    }

    #[Test]
    public function nvdIsAskedForTheOneCveById(): void
    {
        $http = new RecordingHttpClient([self::json(self::recordWith(self::CVE, []))]);

        $this->subject($http)->severityForCve(self::CVE);

        self::assertCount(1, $http->sentRequests());
        $request = $http->sentRequests()[0];
        self::assertSame('GET', $request->getMethod());
        self::assertSame('services.nvd.nist.gov', $request->getUri()->getHost());
        self::assertSame('/rest/json/cves/2.0', $request->getUri()->getPath());
        self::assertSame('cveId=CVE-2026-109162', $request->getUri()->getQuery());
        self::assertSame('application/json', $request->getHeaderLine('Accept'));
        self::assertSame(
            'mteu/advisory-matcher (+https://github.com/mteu/advisory-matcher)',
            $request->getHeaderLine('User-Agent'),
        );
    }

    #[Test]
    public function theEndpointAndUserAgentCanBeSet(): void
    {
        $http = new RecordingHttpClient([self::json(self::recordWith(self::CVE, []))]);

        (new NvdSeverityLookup(
            $http,
            new Psr17Factory(),
            userAgent: 'acme-monitor/2.1 (+https://acme.example/contact)',
            endpoint: 'https://nvd.mirror.example/cves',
        ))->severityForCve(self::CVE);

        $request = $http->sentRequests()[0];
        self::assertSame('https://nvd.mirror.example/cves?cveId=CVE-2026-109162', (string)$request->getUri());
        self::assertSame('acme-monitor/2.1 (+https://acme.example/contact)', $request->getHeaderLine('User-Agent'));
    }

    #[Test]
    public function aRecordWithoutAScoreIsUnknown(): void
    {
        $http = new RecordingHttpClient([self::json(self::recordWith(self::CVE, []))]);

        self::assertSame(Severity::Unknown, $this->subject($http)->severityForCve(self::CVE));
    }

    #[Test]
    public function aCveNvdHasNoRecordOfIsUnknown(): void
    {
        $http = new RecordingHttpClient([self::json(
            '{"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "format": "NVD_CVE", "version": "2.0", "vulnerabilities": []}',
        )]);

        self::assertSame(Severity::Unknown, $this->subject($http)->severityForCve(self::CVE));
    }

    #[Test]
    #[DataProvider('validIdProvider')]
    public function aWellFormedCveIdIsSent(string $cveId): void
    {
        $http = new RecordingHttpClient([self::json(self::recordWith($cveId, []))]);

        $this->subject($http)->severityForCve($cveId);

        self::assertCount(1, $http->sentRequests());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function validIdProvider(): iterable
    {
        yield 'four digit sequence' => ['CVE-2026-1234'];
        yield 'six digit sequence' => [self::CVE];
    }

    #[Test]
    #[DataProvider('malformedIdProvider')]
    public function anIdThatIsNotACveIdIsRejectedWithoutBeingSent(string $cveId): void
    {
        $http = new RecordingHttpClient();

        $answer = $this->subject($http)->severityForCve($cveId);

        self::assertSame([], $http->sentRequests());
        self::assertInstanceOf(SourceFailure::class, $answer);
        self::assertSame(FailureReason::Rejected, $answer->reason);
        self::assertSame('NVD', $answer->sourceName);
        self::assertSame('An id that is not a CVE id was not sent.', $answer->detail);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedIdProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'lower case' => ['cve-2026-1234'];
        yield 'a three digit sequence' => ['CVE-2026-123'];
        yield 'a two digit year' => ['CVE-26-1234'];
        yield 'a prefix' => ['xCVE-2026-1234'];
        yield 'a suffix' => ['CVE-2026-1234x'];
        yield 'a trailing newline' => ["CVE-2026-1234\n"];
        yield 'a smuggled parameter' => ['CVE-2026-1234&cpeName=cpe:2.3:a:php:php'];
        yield 'a GitHub advisory id' => ['GHSA-f57v-q966-7fh6'];
    }

    #[Test]
    public function theApiKeyTravelsTrimmedInAHeaderAndNeverInTheQueryString(): void
    {
        $http = new RecordingHttpClient([self::json(self::recordWith(self::CVE, []))]);

        $this->subject($http, ' ' . self::API_KEY . ' ')->severityForCve(self::CVE);

        $request = $http->sentRequests()[0];
        self::assertSame(self::API_KEY, $request->getHeaderLine('apiKey'));
        self::assertStringNotContainsString(self::API_KEY, (string)$request->getUri());
    }

    #[Test]
    public function withoutAKeyNoKeyHeaderIsSent(): void
    {
        $http = new RecordingHttpClient([self::json(self::recordWith(self::CVE, []))]);

        $this->subject($http, '   ')->severityForCve(self::CVE);

        self::assertFalse($http->sentRequests()[0]->hasHeader('apiKey'));
    }

    #[Test]
    public function a403IsARejectionWhoseDetailCarriesNoCredential(): void
    {
        $logger = new CollectingLogger();
        $http = new RecordingHttpClient([new Response(403, [], 'Forbidden')]);

        $answer = $this->subject($http, self::API_KEY, $logger)->severityForCve(self::CVE);

        self::assertInstanceOf(SourceFailure::class, $answer);
        self::assertSame(FailureReason::Rejected, $answer->reason);
        self::assertSame('NVD answered 403 to GET /rest/json/cves/2.0.', $answer->detail);
        self::assertStringNotContainsString(self::API_KEY, $logger->transcript());
    }

    #[Test]
    public function a429IsRateLimitedAndCarriesRetryAfter(): void
    {
        $http = new RecordingHttpClient([new Response(429, ['Retry-After' => '30'])]);

        $answer = $this->subject($http)->severityForCve(self::CVE);

        self::assertInstanceOf(SourceFailure::class, $answer);
        self::assertSame(FailureReason::RateLimited, $answer->reason);
        self::assertSame(30, $answer->retryAfterSeconds);
    }

    #[Test]
    public function aBodyNotInTheDocumentedShapeIsUnparseable(): void
    {
        $answer = $this->subject(new RecordingHttpClient([self::json('{"vulnerabilities": []}')]))->severityForCve(self::CVE);

        self::assertInstanceOf(SourceFailure::class, $answer);
        self::assertSame(FailureReason::Unparseable, $answer->reason);
    }

    #[Test]
    public function nothingIsStoredSoEveryAnswerCostsALookup(): void
    {
        self::assertSame([], $this->subject(new RecordingHttpClient())->storedSeveritiesForCves([self::CVE]));
    }

    private function subject(
        RecordingHttpClient $http,
        string $apiKey = '',
        CollectingLogger $logger = new CollectingLogger(),
    ): NvdSeverityLookup {
        return new NvdSeverityLookup(
            httpClient: $http,
            requestFactory: new Psr17Factory(),
            apiKey: $apiKey,
            logger: $logger,
        );
    }

    private static function json(string $body): ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'application/json'], $body);
    }

    /**
     * @param array<string, mixed> $metrics
     */
    private static function recordWith(string $cveId, array $metrics): string
    {
        return json_encode([
            'resultsPerPage' => 1,
            'startIndex' => 0,
            'totalResults' => 1,
            'format' => 'NVD_CVE',
            'version' => '2.0',
            'vulnerabilities' => [[
                'cve' => [
                    'id' => $cveId,
                    'vulnStatus' => 'Analyzed',
                    'published' => '2026-10-13T09:15:00.000',
                    'metrics' => $metrics,
                ],
            ]],
        ], JSON_THROW_ON_ERROR);
    }
}
