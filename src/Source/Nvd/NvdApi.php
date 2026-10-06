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

namespace mteu\AdvisoryMatcher\Source\Nvd;

use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\Http\BoundedBodyReader;
use mteu\AdvisoryMatcher\Source\Http\HttpFailureClassifier;
use mteu\AdvisoryMatcher\Source\Http\ResponseBodyUnreadable;
use mteu\AdvisoryMatcher\Source\Http\ResponseTooLarge;
use mteu\AdvisoryMatcher\Source\Http\UserAgent;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;

/**
 * @internal
 */
final readonly class NvdApi
{
    /** NVD's own maximum page size for this endpoint. */
    private const int RESULTS_PER_PAGE = 2000;

    private const int MAX_PAGES = 5;

    public function __construct(
        private ClientInterface $httpClient,
        private RequestFactoryInterface $requestFactory,
        private BoundedBodyReader $bodyReader,
        private HttpFailureClassifier $failureClassifier,
        private LoggerInterface $logger,
        private string $endpoint,
        #[\SensitiveParameter]
        private string $apiKey,
        private UserAgent $userAgent,
    ) {
    }

    /**
     * @return list<array<string, mixed>>|SourceFailure
     */
    public function findVulnerabilities(string $cpeName): array|SourceFailure
    {
        $records = [];

        for ($page = 0; $page < self::MAX_PAGES; ++$page) {
            $startIndex = $page * self::RESULTS_PER_PAGE;
            $read = $this->readPage($cpeName, $startIndex);

            if ($read instanceof SourceFailure) {
                return $read;
            }

            $records = [...$records, ...$read['records']];

            if ($startIndex + self::RESULTS_PER_PAGE >= $read['totalResults']) {
                return $records;
            }
        }

        return $this->failure(
            FailureReason::Unparseable,
            sprintf('NVD was still paging after %d pages of %d records.', self::MAX_PAGES, self::RESULTS_PER_PAGE),
        );
    }

    /**
     * @return array{records: list<array<string, mixed>>, totalResults: int}|SourceFailure
     */
    private function readPage(string $cpeName, int $startIndex): array|SourceFailure
    {
        $query = http_build_query([
            'cpeName' => $cpeName,
            // Valueless flags in NVD's grammar. Empty value is how they are spelled out in the query string.
            'isVulnerable' => '',
            'noRejected' => '',
            'resultsPerPage' => self::RESULTS_PER_PAGE,
            'startIndex' => $startIndex,
        ]);

        $request = $this->userAgent->applyTo(
            $this->requestFactory->createRequest('GET', $this->endpoint . '?' . $query)
                ->withHeader('Accept', 'application/json'),
        );

        if ($this->apiKey !== '') {
            $request = $request->withHeader('apiKey', $this->apiKey);
        }

        $decoded = $this->send($request);

        if ($decoded instanceof SourceFailure) {
            return $decoded;
        }

        $vulnerabilities = $decoded['vulnerabilities'] ?? null;
        $totalResults = $decoded['totalResults'] ?? null;

        if (!is_array($vulnerabilities) || !array_is_list($vulnerabilities) || !is_int($totalResults)) {
            return $this->failure(
                FailureReason::Unparseable,
                'The response carries no "vulnerabilities" list and "totalResults" count.',
            );
        }

        $records = [];

        foreach ($vulnerabilities as $entry) {
            $cve = is_array($entry) ? ($entry['cve'] ?? null) : null;

            // Dropping an entry that could not be read would potentially drop a vulnerability.
            if (!is_array($cve)) {
                return $this->failure(FailureReason::Unparseable, 'An entry carries no "cve" object.');
            }

            $records[] = $this->stringKeyed($cve);
        }

        return ['records' => $records, 'totalResults' => $totalResults];
    }

    /**
     * @return array<string, mixed>|SourceFailure
     */
    private function send(RequestInterface $request): array|SourceFailure
    {
        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $exception) {
            // The message only, not the exception: a PSR-18 exception carries the request, and the request carries the API key.
            $this->logger->warning('NVD request failed.', ['message' => $exception->getMessage()]);

            return $this->failure(
                $this->failureClassifier->reasonForTransportFailure($exception),
                $exception->getMessage(),
            );
        }

        $status = $response->getStatusCode();

        if ($status < 200 || $status >= 300) {
            return $this->failureForStatus($request, $response);
        }

        try {
            $decoded = json_decode($this->bodyReader->read($response), true, 512, JSON_THROW_ON_ERROR);
        } catch (ResponseTooLarge $exception) {
            return $this->failure(FailureReason::Unparseable, $exception->getMessage());
        } catch (ResponseBodyUnreadable $exception) {
            $this->logger->warning('NVD response could not be read.', ['message' => $exception->getMessage()]);

            return $this->failure(
                $this->failureClassifier->reasonForUnreadableBody($exception),
                $exception->getMessage(),
            );
        } catch (\JsonException $exception) {
            return $this->failure(FailureReason::Unparseable, 'The response is not JSON: ' . $exception->getMessage());
        }

        if (!is_array($decoded) || ($decoded !== [] && array_is_list($decoded))) {
            return $this->failure(FailureReason::Unparseable, 'The response is not a JSON object.');
        }

        return $this->stringKeyed($decoded);
    }

    private function failureForStatus(RequestInterface $request, ResponseInterface $response): SourceFailure
    {
        $status = $response->getStatusCode();
        $reason = $this->failureClassifier->reasonForStatus($status);

        return new SourceFailure(
            sourceName: NvdAdvisorySource::NAME,
            ecosystem: Ecosystem::Php,
            reason: $reason,
            detail: sprintf('NVD answered %d to %s %s.', $status, $request->getMethod(), $request->getUri()->getPath()),
            retryAfterSeconds: $reason === FailureReason::RateLimited
                ? $this->failureClassifier->retryAfterSeconds($response)
                : null,
        );
    }

    private function failure(FailureReason $reason, string $detail): SourceFailure
    {
        return new SourceFailure(NvdAdvisorySource::NAME, Ecosystem::Php, $reason, $detail);
    }

    /**
     * @param array<mixed> $decoded
     * @return array<string, mixed>
     */
    private function stringKeyed(array $decoded): array
    {
        $keyed = [];

        foreach ($decoded as $key => $value) {
            if (is_string($key)) {
                $keyed[$key] = $value;
            }
        }

        return $keyed;
    }
}
