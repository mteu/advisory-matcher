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

namespace mteu\AdvisoryMatcher\Tests\Unit\Source\Packagist;

use mteu\AdvisoryMatcher\Package\ComposerPackageNameValidator;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\AdvisoryBatch;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Source\Packagist\PackagistAdvisorySource;
use mteu\AdvisoryMatcher\Tests\Unit\Clock\FrozenClock;
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
use Psr\Http\Message\ResponseInterface;

#[CoversClass(PackagistAdvisorySource::class)]
final class PackagistAdvisorySourceTest extends TestCase
{
    private const string ENDPOINT = 'https://packagist.org/api/security-advisories/';

    private const string LIBRARY_USER_AGENT = 'mteu/advisory-matcher (+https://github.com/mteu/advisory-matcher)';

    private const string CONSUMER_USER_AGENT = 'acme-monitor/2.1 (+https://acme.example/contact)';

    private const int MAX_RESPONSE_BYTES = 25 * 1024 * 1024;

    private const int RESPONSE_CHUNK_BYTES = 65536;

    #[Test]
    public function aPackageTheResponseOmitsIsAbsentFromAnsweredFor(): void
    {
        $monolog = $this->composer('monolog/monolog');
        $clean = $this->composer('psr/log');
        $unknown = $this->composer('nonexistent-vendor-zz/nope');

        $batch = $this->ask([$monolog, $clean, $unknown], self::fixture('monolog-psr-log-and-unknown.json'));

        self::assertTrue($batch->isComplete());
        self::assertTrue($batch->wasAnsweredFor($monolog));
        self::assertTrue($batch->wasAnsweredFor($clean), 'A known package with no advisories is an answer.');
        self::assertFalse($batch->wasAnsweredFor($unknown), 'A package Packagist does not list was not answered for.');

        self::assertCount(1, $batch->advisoriesFor($monolog));
        self::assertSame([], $batch->advisoriesFor($clean));
    }

    #[Test]
    public function noKnownPackageIsAnAnswerForNobodyRatherThanAFailure(): void
    {
        $unknown = $this->composer('nonexistent-vendor-zz/nope');

        $batch = $this->ask([$unknown], self::fixture('nothing-known.json'));

        self::assertSame([], $batch->failures);
        self::assertSame([], $batch->answeredFor);
    }

    #[Test]
    public function a429IsRateLimitedWithRetryAfterReadOffTheHeader(): void
    {
        $package = $this->composer('monolog/monolog');

        $batch = $this->ask([$package], new Response(429, ['Retry-After' => '120']));

        self::assertCount(1, $batch->failures);
        self::assertSame(FailureReason::RateLimited, $batch->failures[0]->reason);
        self::assertSame(120, $batch->failures[0]->retryAfterSeconds);
        self::assertSame(Ecosystem::Composer, $batch->failures[0]->ecosystem);
        self::assertSame('Packagist', $batch->failures[0]->sourceName);
        self::assertFalse($batch->wasAnsweredFor($package));
    }

    #[Test]
    public function aRetryAfterDateIsReportedAsNoAdviceRatherThanGuessed(): void
    {
        $batch = $this->ask(
            [$this->composer('monolog/monolog')],
            new Response(429, ['Retry-After' => 'Wed, 21 Oct 2026 07:28:00 GMT']),
        );

        self::assertSame(FailureReason::RateLimited, $batch->failures[0]->reason);
        self::assertNull($batch->failures[0]->retryAfterSeconds);
    }

    /**
     * @return \Generator<string, array{string}>
     */
    public static function bodiesThatAreNotTheDocumentedShape(): \Generator
    {
        yield 'truncated mid-record' => [self::fixture('truncated.json')];
        yield 'an error envelope on a 200' => [self::fixture('missing-packages-parameter.json')];
        yield 'not JSON at all' => ['<html>Service Unavailable</html>'];
        yield 'a JSON scalar' => ['"advisories"'];
        yield 'advisories as a non-empty list' => ['{"advisories": [{"advisoryId": "PKSA-1"}]}'];
        yield 'advisories as a string' => ['{"advisories": "none"}'];
        yield 'empty body' => [''];
    }

    #[Test]
    #[DataProvider('bodiesThatAreNotTheDocumentedShape')]
    public function a2xxBodyThatIsNotTheDocumentedShapeIsUnparseableRatherThanAnException(string $body): void
    {
        $package = $this->composer('monolog/monolog');

        $batch = $this->ask([$package], $body);

        self::assertCount(1, $batch->failures);
        self::assertSame(FailureReason::Unparseable, $batch->failures[0]->reason);
        self::assertFalse($batch->wasAnsweredFor($package));
        self::assertSame([], $batch->advisories);
    }

    #[Test]
    public function aBodyOverTheSizeGuardIsRefusedWithoutBeingFullyBuffered(): void
    {
        $body = new EndlessStream();

        $batch = $this->ask([$this->composer('monolog/monolog')], (new Response(200))->withBody($body));

        self::assertSame(FailureReason::Unparseable, $batch->failures[0]->reason);
        self::assertSame(
            intdiv(self::MAX_RESPONSE_BYTES, self::RESPONSE_CHUNK_BYTES) + 1,
            $body->reads(),
            'The read has to stop at the first chunk past the cap.',
        );
    }

    #[Test]
    public function aBodyThatBreaksOffMidReadIsAnUnreachableFeedRatherThanAThrow(): void
    {
        $package = $this->composer('monolog/monolog');

        $batch = $this->ask([$package], (new Response(200))->withBody(new ResettingStream()));

        self::assertCount(1, $batch->failures);
        self::assertSame(FailureReason::Unreachable, $batch->failures[0]->reason);
        self::assertStringContainsString('Connection reset by peer', $batch->failures[0]->detail);
        self::assertFalse($batch->wasAnsweredFor($package));
        self::assertSame([], $batch->advisories);
    }

    #[Test]
    public function anOversizedContentLengthIsRefusedBeforeTheBodyIsRead(): void
    {
        $body = new EndlessStream();
        $response = (new Response(200, ['Content-Length' => (string)(26 * 1024 * 1024)]))->withBody($body);

        $batch = $this->ask([$this->composer('monolog/monolog')], $response);

        self::assertSame(FailureReason::Unparseable, $batch->failures[0]->reason);
        self::assertSame(0, $body->reads());
    }

    /**
     * @return \Generator<string, array{ResponseInterface|ClientExceptionInterface, FailureReason}>
     */
    public static function unansweredRequests(): \Generator
    {
        $request = new Request('POST', self::ENDPOINT);

        yield 'connection refused' => [new NetworkFailure($request, 'cURL error 7: Failed to connect'), FailureReason::Unreachable];
        yield 'timed out' => [
            new NetworkFailure($request, 'cURL error 28: Operation timed out after 10001 milliseconds'),
            FailureReason::Timeout,
        ];
        yield 'service unavailable' => [new Response(503), FailureReason::Unreachable];
        yield 'not found' => [new Response(404), FailureReason::Rejected];
        yield 'a redirect the client was told not to follow' => [new Response(301), FailureReason::Rejected];
    }

    #[Test]
    #[DataProvider('unansweredRequests')]
    public function anUnansweredRequestIsClassifiedByWhatWentWrong(
        ResponseInterface|ClientExceptionInterface $answer,
        FailureReason $expected,
    ): void {
        $package = $this->composer('monolog/monolog');

        $batch = $this->ask([$package], $answer);

        self::assertCount(1, $batch->failures);
        self::assertSame($expected, $batch->failures[0]->reason);
        self::assertFalse($batch->wasAnsweredFor($package));
    }

    #[Test]
    public function sendsOneFormEncodedPostForAllPackages(): void
    {
        $http = new RecordingHttpClient([new Response(200, [], '{"advisories": []}')]);

        $this->subject($http)->advisoriesFor([$this->composer('vendor/foo'), $this->composer('vendor/bar')]);

        $requests = $http->sentRequests();
        self::assertCount(1, $requests);
        self::assertSame('POST', $requests[0]->getMethod());
        self::assertSame(self::ENDPOINT, (string)$requests[0]->getUri());
        self::assertSame('application/x-www-form-urlencoded', $requests[0]->getHeaderLine('Content-Type'));
        self::assertSame('application/json', $requests[0]->getHeaderLine('Accept'));
        self::assertSame(
            'packages[]=' . urlencode('vendor/foo') . '&packages[]=' . urlencode('vendor/bar'),
            (string)$requests[0]->getBody(),
        );
    }

    #[Test]
    public function aCraftedPackageNameCannotForgeAdditionalQueryParameters(): void
    {
        $http = new RecordingHttpClient([new Response(200, [], '{"advisories": {"vendor/real": []}}')]);
        $crafted = $this->composer('evil/pkg&packages[]=dropped');
        $real = $this->composer('vendor/real');

        $batch = $this->subject($http)->advisoriesFor([$crafted, $real]);

        self::assertSame('packages[]=' . urlencode('vendor/real'), (string)$http->sentRequests()[0]->getBody());
        self::assertTrue($batch->wasAnsweredFor($real));
        self::assertFalse($batch->wasAnsweredFor($crafted));
        self::assertCount(1, $batch->failures);
        self::assertSame(FailureReason::Rejected, $batch->failures[0]->reason);
    }

    #[Test]
    public function aQueryLeftWithNoUsableNameFailsWithoutARequest(): void
    {
        $http = new RecordingHttpClient();

        $batch = $this->subject($http)->advisoriesFor([$this->composer('no-vendor-segment')]);

        self::assertSame([], $http->sentRequests());
        self::assertSame(FailureReason::Rejected, $batch->failures[0]->reason);
        self::assertSame([], $batch->answeredFor);
    }

    #[Test]
    public function packagesOutsideComposerAreNeitherAskedAboutNorAFailure(): void
    {
        $http = new RecordingHttpClient();
        $npm = new PackageRef(Ecosystem::Npm, 'lodash', '4.17.20');

        $batch = $this->subject($http)->advisoriesFor([$npm]);

        self::assertSame([], $http->sentRequests());
        self::assertTrue($batch->isComplete());
        self::assertFalse($batch->wasAnsweredFor($npm));
    }

    #[Test]
    public function anEmptyQuestionMakesNoRequest(): void
    {
        $http = new RecordingHttpClient();

        $batch = $this->subject($http)->advisoriesFor([]);

        self::assertSame([], $http->sentRequests());
        self::assertEquals(new AdvisoryBatch(), $batch);
    }

    #[Test]
    public function advisoriesAreFiledUnderTheRequestedSpelling(): void
    {
        $package = $this->composer('PHPMailer/PHPMailer');

        $batch = $this->ask([$package], self::fixture('phpmailer.json'));

        self::assertTrue($batch->wasAnsweredFor($package));
        self::assertCount(14, $batch->advisoriesFor($package));
    }

    #[Test]
    public function answersUnderTwoSpellingsOfOneNameAreMergedNotOverwritten(): void
    {
        $package = $this->composer('PHPMailer/PHPMailer');
        $records = $this->decodedFixture('phpmailer.json')['advisories']['phpmailer/phpmailer'];

        $body = json_encode(
            ['advisories' => ['phpmailer/phpmailer' => $records, 'PHPMailer/PHPMailer' => []]],
            JSON_THROW_ON_ERROR,
        );

        $batch = $this->ask([$package], $body);

        self::assertCount(14, $batch->advisoriesFor($package));
    }

    #[Test]
    public function anAdvisoryListedTwiceIsKeptOnce(): void
    {
        $package = $this->composer('vendor/example');
        $record = ['advisoryId' => 'PKSA-1', 'packageName' => 'vendor/example', 'affectedVersions' => '<1.0'];
        $body = json_encode(
            ['advisories' => ['vendor/example' => [$record], 'VENDOR/example' => [$record]]],
            JSON_THROW_ON_ERROR,
        );

        $batch = $this->ask([$package], $body);

        self::assertCount(1, $batch->advisoriesFor($package));
    }

    #[Test]
    public function aRecordWithoutAnAdvisoryIdIsSkipped(): void
    {
        $package = $this->composer('vendor/example');

        $batch = $this->ask([$package], '{"advisories": {"vendor/example": [{"title": "no id"}, "not a record"]}}');

        self::assertTrue($batch->wasAnsweredFor($package));
        self::assertSame([], $batch->advisoriesFor($package));
    }

    #[Test]
    public function onePackageAtTwoVersionsIsQueriedOnceAndAnsweredForBoth(): void
    {
        $http = new RecordingHttpClient([new Response(200, [], self::fixture('monolog-psr-log-and-unknown.json'))]);
        $older = new PackageRef(Ecosystem::Composer, 'monolog/monolog', '1.10.0');
        $newer = new PackageRef(Ecosystem::Composer, 'monolog/monolog', '3.0.0');

        $batch = $this->subject($http)->advisoriesFor([$older, $newer]);

        self::assertSame('packages[]=' . urlencode('monolog/monolog'), (string)$http->sentRequests()[0]->getBody());
        self::assertTrue($batch->wasAnsweredFor($older));
        self::assertTrue($batch->wasAnsweredFor($newer));
        self::assertCount(1, $batch->advisoriesFor($older));
        self::assertEquals($batch->advisoriesFor($older), $batch->advisoriesFor($newer));
    }

    #[Test]
    public function everyRequestNamesTheLibraryUnlessTheConsumerNamesItself(): void
    {
        $factory = new Psr17Factory();
        $http = new RecordingHttpClient([self::noAdvisories(), self::noAdvisories()]);

        (new PackagistAdvisorySource($http, $factory, $factory))->advisoriesFor([$this->composer('vendor/one')]);
        (new PackagistAdvisorySource($http, $factory, $factory, userAgent: self::CONSUMER_USER_AGENT))
            ->advisoriesFor([$this->composer('vendor/one')]);

        self::assertSame(self::LIBRARY_USER_AGENT, $http->sentRequests()[0]->getHeaderLine('User-Agent'));
        self::assertSame(self::CONSUMER_USER_AGENT, $http->sentRequests()[1]->getHeaderLine('User-Agent'));
    }

    #[Test]
    public function anEmptyUserAgentLeavesTheHeaderToTheHttpClient(): void
    {
        $factory = new Psr17Factory();
        $http = new RecordingHttpClient([self::noAdvisories()]);

        (new PackagistAdvisorySource($http, $factory, $factory, userAgent: ''))->advisoriesFor([$this->composer('vendor/one')]);

        self::assertFalse($http->sentRequests()[0]->hasHeader('User-Agent'));
    }

    #[Test]
    public function aRecordWithoutADateIsDatedByTheClockTheConsumerPasses(): void
    {
        $factory = new Psr17Factory();
        $package = $this->composer('vendor/example');
        $http = new RecordingHttpClient([new Response(200, [], (string)json_encode(
            ['advisories' => ['vendor/example' => [['advisoryId' => 'PKSA-1', 'packageName' => 'vendor/example', 'affectedVersions' => '<1.0']]]],
        ))]);

        $source = new PackagistAdvisorySource($http, $factory, $factory, clock: FrozenClock::at('2020-02-02T00:00:00+00:00'));

        self::assertEquals(
            new \DateTimeImmutable('2020-02-02T00:00:00+00:00'),
            $source->advisoriesFor([$package])->advisoriesFor($package)[0]->reportedAt,
        );
    }

    #[Test]
    public function coversComposerAndNothingElse(): void
    {
        $subject = $this->subject(new RecordingHttpClient());

        self::assertSame('Packagist', $subject->name());
        self::assertSame([Ecosystem::Composer], $subject->coveredEcosystems());
    }

    /**
     * @param list<PackageRef> $packages
     */
    private function ask(array $packages, ResponseInterface|ClientExceptionInterface|string $answer): AdvisoryBatch
    {
        $response = is_string($answer) ? new Response(200, ['Content-Type' => 'application/json'], $answer) : $answer;

        return $this->subject(new RecordingHttpClient([$response]))->advisoriesFor($packages);
    }

    private static function noAdvisories(): ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'application/json'], '{"advisories": []}');
    }

    private function subject(RecordingHttpClient $http): PackagistAdvisorySource
    {
        $factory = new Psr17Factory();

        return new PackagistAdvisorySource(
            httpClient: $http,
            requestFactory: $factory,
            streamFactory: $factory,
            clock: FrozenClock::at('2026-09-24T12:00:00+00:00'),
            validator: new ComposerPackageNameValidator(),
        );
    }

    private function composer(string $name): PackageRef
    {
        return new PackageRef(Ecosystem::Composer, $name, '1.0.0');
    }

    private static function fixture(string $name): string
    {
        $contents = file_get_contents(__DIR__ . '/Fixtures/' . $name);
        self::assertIsString($contents);

        return $contents;
    }

    /**
     * @return array{advisories: array<string, list<array<string, mixed>>>}
     */
    private function decodedFixture(string $name): array
    {
        /** @var array{advisories: array<string, list<array<string, mixed>>>} $decoded */
        $decoded = json_decode(self::fixture($name), true, 512, JSON_THROW_ON_ERROR);

        return $decoded;
    }
}
