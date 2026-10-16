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

namespace mteu\AdvisoryMatcher\Source\Packagist;

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\Packagist\PackagistAdvisoryNormalizer;
use mteu\AdvisoryMatcher\Clock\SystemClock;
use mteu\AdvisoryMatcher\Package\ComposerPackageNameValidator;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Source\AdvisoryBatch;
use mteu\AdvisoryMatcher\Source\AdvisorySource;
use mteu\AdvisoryMatcher\Source\AnsweredPackage;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\Http\BoundedBodyReader;
use mteu\AdvisoryMatcher\Source\Http\HttpFailureClassifier;
use mteu\AdvisoryMatcher\Source\Http\ResponseBodyUnreadable;
use mteu\AdvisoryMatcher\Source\Http\ResponseTooLarge;
use mteu\AdvisoryMatcher\Source\Http\UserAgent;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final readonly class PackagistAdvisorySource implements AdvisorySource
{
    public const string NAME = 'Packagist';

    private UserAgent $userAgent;

    private PackagistAdvisoryNormalizer $normalizer;

    public function __construct(
        private ClientInterface $httpClient,
        private RequestFactoryInterface $requestFactory,
        private StreamFactoryInterface $streamFactory,
        private LoggerInterface $logger = new NullLogger(),
        string $userAgent = UserAgent::LIBRARY_DEFAULT,
        ClockInterface $clock = new SystemClock(),
        private string $endpoint = 'https://packagist.org/api/security-advisories/',
        private ComposerPackageNameValidator $validator = new ComposerPackageNameValidator(),
        private BoundedBodyReader $bodyReader = new BoundedBodyReader(),
        private HttpFailureClassifier $failureClassifier = new HttpFailureClassifier(),
    ) {
        $this->userAgent = new UserAgent($userAgent);
        $this->normalizer = new PackagistAdvisoryNormalizer($clock);
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function coveredEcosystems(): array
    {
        return [Ecosystem::Composer];
    }

    public function advisoriesFor(array $packages): AdvisoryBatch
    {
        $queryable = [];
        $refused = [];

        foreach ($packages as $package) {
            if ($package->ecosystem !== Ecosystem::Composer) {
                continue;
            }

            if ($this->validator->isValid($package->name)) {
                $queryable[] = $package;
            } else {
                $refused[] = $package->name;
            }
        }

        $failures = $refused === [] ? [] : [$this->refusedNamesFailure($refused)];

        if ($queryable === []) {
            return new AdvisoryBatch(failures: $failures);
        }

        $answer = $this->ask($this->distinctNames($queryable));

        if ($answer instanceof SourceFailure) {
            return new AdvisoryBatch(failures: [...$failures, $answer]);
        }

        return new AdvisoryBatch(
            answeredFor: $this->answeredPackages($queryable, $answer),
            failures: $failures,
        );
    }

    /**
     * @param list<string> $names
     * @return array<string, list<mixed>>|SourceFailure
     */
    private function ask(array $names): array|SourceFailure
    {
        try {
            $response = $this->httpClient->sendRequest($this->buildRequest($names));
        } catch (ClientExceptionInterface $exception) {
            $this->logger->warning('Packagist advisory request failed.', ['exception' => $exception]);

            return $this->failure(
                $this->failureClassifier->reasonForTransportFailure($exception),
                $exception->getMessage(),
            );
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            return $this->failureForStatus($response);
        }

        try {
            $body = $this->bodyReader->read($response);
        } catch (ResponseTooLarge $exception) {
            return $this->failure(FailureReason::Unparseable, $exception->getMessage());
        } catch (ResponseBodyUnreadable $exception) {
            $this->logger->warning(
                'Packagist advisory response could not be read.',
                ['message' => $exception->getMessage()],
            );

            return $this->failure(
                $this->failureClassifier->reasonForUnreadableBody($exception),
                $exception->getMessage(),
            );
        }

        return $this->indexByPackage($body);
    }

    /**
     * @param list<string> $names
     */
    private function buildRequest(array $names): RequestInterface
    {
        $formParts = array_map(
            static fn (string $name): string => 'packages[]=' . urlencode($name),
            $names,
        );

        $request = $this->requestFactory->createRequest('POST', $this->endpoint)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream(implode('&', $formParts)));

        return $this->userAgent->applyTo($request);
    }

    private function failureForStatus(ResponseInterface $response): SourceFailure
    {
        $status = $response->getStatusCode();
        $reason = $this->failureClassifier->reasonForStatus($status);

        return new SourceFailure(
            sourceName: self::NAME,
            ecosystem: Ecosystem::Composer,
            reason: $reason,
            detail: $reason === FailureReason::RateLimited
                ? 'Packagist answered 429 Too Many Requests.'
                : sprintf('Packagist answered %d.', $status),
            retryAfterSeconds: $reason === FailureReason::RateLimited
                ? $this->failureClassifier->retryAfterSeconds($response)
                : null,
        );
    }

    /**
     * @return array<string, list<mixed>>|SourceFailure
     */
    private function indexByPackage(string $body): array|SourceFailure
    {
        try {
            $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            return $this->failure(FailureReason::Unparseable, 'The response is not JSON: ' . $exception->getMessage());
        }

        $advisories = is_array($decoded) ? ($decoded['advisories'] ?? null) : null;

        if (!is_array($advisories) || ($advisories !== [] && array_is_list($advisories))) {
            return $this->failure(FailureReason::Unparseable, 'The response has no "advisories" map.');
        }

        $index = [];

        foreach ($advisories as $name => $records) {
            if (!is_string($name) || !is_array($records)) {
                continue;
            }

            $key = strtolower($name);
            $index[$key] = [...($index[$key] ?? []), ...array_values($records)];
        }

        return $index;
    }

    /**
     * @param list<PackageRef> $queryable
     * @param array<string, list<mixed>> $index
     * @return list<AnsweredPackage>
     */
    private function answeredPackages(array $queryable, array $index): array
    {
        $answered = [];

        foreach ($queryable as $package) {
            $records = $index[strtolower($package->name)] ?? null;

            if ($records !== null) {
                $answered[] = new AnsweredPackage($package, advisories: $this->normalizeRecords($records, $package->package));
            }
        }

        return $answered;
    }

    /**
     * @param list<mixed> $records
     * @return list<Advisory>
     */
    private function normalizeRecords(array $records, PackageUrl $package): array
    {
        $advisories = [];
        $seen = [];

        foreach ($records as $record) {
            if (!is_array($record)) {
                continue;
            }

            $advisoryId = $record['advisoryId'] ?? null;
            if (!is_string($advisoryId) || $advisoryId === '' || array_key_exists($advisoryId, $seen)) {
                continue;
            }

            $seen[$advisoryId] = true;
            $advisories[] = $this->normalizer->normalize($record, $package);
        }

        return $advisories;
    }

    /**
     * @param non-empty-list<string> $names
     */
    private function refusedNamesFailure(array $names): SourceFailure
    {
        $this->logger->warning(
            'Excluded package names that do not match Composer\'s naming grammar from the Packagist advisory query.',
            ['packages' => $names],
        );

        return $this->failure(
            FailureReason::Rejected,
            sprintf('%d package name(s) outside Composer\'s naming grammar were not sent.', count($names)),
        );
    }

    /**
     * @param list<PackageRef> $packages
     * @return list<string>
     */
    private function distinctNames(array $packages): array
    {
        return array_values(array_unique(array_map(
            static fn (PackageRef $package): string => $package->name,
            $packages,
        )));
    }

    private function failure(FailureReason $reason, string $detail): SourceFailure
    {
        return new SourceFailure(
            sourceName: self::NAME,
            ecosystem: Ecosystem::Composer,
            reason: $reason,
            detail: $detail,
        );
    }
}
