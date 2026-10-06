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

namespace mteu\AdvisoryMatcher\Source\Osv;

use mteu\AdvisoryMatcher\Source\FailureReason;
use mteu\AdvisoryMatcher\Source\Http\BoundedBodyReader;
use mteu\AdvisoryMatcher\Source\Http\HttpFailureClassifier;
use mteu\AdvisoryMatcher\Source\Http\ResponseBodyUnreadable;
use mteu\AdvisoryMatcher\Source\Http\ResponseTooLarge;
use mteu\AdvisoryMatcher\Source\Http\UserAgent;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;

/**
 * @internal
 */
final readonly class OsvApi
{
    private const int MAX_PAGES = 10;

    private const string VULNERABILITY_ID_PATTERN = '/\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z/';

    public function __construct(
        private ClientInterface $httpClient,
        private RequestFactoryInterface $requestFactory,
        private StreamFactoryInterface $streamFactory,
        private BoundedBodyReader $bodyReader,
        private HttpFailureClassifier $failureClassifier,
        private LoggerInterface $logger,
        private string $endpoint,
        private UserAgent $userAgent,
    ) {
    }

    /**
     * @param non-empty-list<OsvQuery> $queries
     * @return list<list<OsvVulnerabilityReference>>|OsvCallFailure
     */
    public function findVulnerabilities(array $queries): array|OsvCallFailure
    {
        $found = array_fill(0, count($queries), []);
        $pageTokens = array_fill(0, count($queries), '');
        $pending = array_keys($queries);

        for ($page = 1; $pending !== []; ++$page) {
            if ($page > self::MAX_PAGES) {
                return new OsvCallFailure(
                    FailureReason::Unparseable,
                    sprintf('OSV was still paging after %d pages.', self::MAX_PAGES),
                );
            }

            $results = $this->queryBatch($queries, $pending, $pageTokens);

            if ($results instanceof OsvCallFailure) {
                return $results;
            }

            $stillPaging = [];

            foreach ($pending as $position => $index) {
                $found[$index] = [...$found[$index], ...$results[$position]['vulns']];

                if ($results[$position]['nextPageToken'] !== '') {
                    $pageTokens[$index] = $results[$position]['nextPageToken'];
                    $stillPaging[] = $index;
                }
            }

            $pending = $stillPaging;
        }

        return $found;
    }

    /**
     * @return array<string, mixed>|OsvCallFailure
     */
    public function fetchVulnerability(string $id): array|OsvCallFailure
    {
        $request = $this->requestFactory->createRequest('GET', $this->endpoint . 'vulns/' . rawurlencode($id))
            ->withHeader('Accept', 'application/json');

        $decoded = $this->send($request);

        if ($decoded instanceof OsvCallFailure) {
            return $decoded;
        }

        if (!is_string($decoded['id'] ?? null) || trim($decoded['id']) === '') {
            return new OsvCallFailure(FailureReason::Unparseable, sprintf('The record for %s carries no id.', $id));
        }

        return $decoded;
    }

    /**
     * @param non-empty-list<OsvQuery> $queries
     * @param non-empty-list<int> $pending positions in $queries to send
     * @param array<int, string> $pageTokens per position in $queries; '' for the first page
     * @return list<array{vulns: list<OsvVulnerabilityReference>, nextPageToken: string}>|OsvCallFailure
     */
    private function queryBatch(array $queries, array $pending, array $pageTokens): array|OsvCallFailure
    {
        $payload = [];

        foreach ($pending as $index) {
            $query = ['package' => ['name' => $queries[$index]->name, 'ecosystem' => $queries[$index]->label()]];

            if ($pageTokens[$index] !== '') {
                $query['page_token'] = $pageTokens[$index];
            }

            $payload[] = $query;
        }

        $request = $this->requestFactory->createRequest('POST', $this->endpoint . 'querybatch')
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream(json_encode(['queries' => $payload], JSON_THROW_ON_ERROR)));

        $decoded = $this->send($request);

        if ($decoded instanceof OsvCallFailure) {
            return $decoded;
        }

        $results = $decoded['results'] ?? null;

        if (!is_array($results) || !array_is_list($results)) {
            return new OsvCallFailure(FailureReason::Unparseable, 'The response has no "results" list.');
        }

        if (count($results) !== count($pending)) {
            return new OsvCallFailure(
                FailureReason::Unparseable,
                sprintf('OSV answered %d of %d queries.', count($results), count($pending)),
            );
        }

        $read = [];

        foreach ($results as $result) {
            $parsed = $this->readResult($result);

            if ($parsed instanceof OsvCallFailure) {
                return $parsed;
            }

            $read[] = $parsed;
        }

        return $read;
    }

    /**
     * @return array{vulns: list<OsvVulnerabilityReference>, nextPageToken: string}|OsvCallFailure
     */
    private function readResult(mixed $result): array|OsvCallFailure
    {
        if (!is_array($result)) {
            return new OsvCallFailure(FailureReason::Unparseable, 'A query result is not an object.');
        }

        $vulns = $result['vulns'] ?? [];

        if (!is_array($vulns) || !array_is_list($vulns)) {
            return new OsvCallFailure(FailureReason::Unparseable, 'A query result carries no "vulns" list.');
        }

        $references = [];

        foreach ($vulns as $vuln) {
            $id = is_array($vuln) ? ($vuln['id'] ?? null) : null;

            if (!is_string($id) || preg_match(self::VULNERABILITY_ID_PATTERN, $id) !== 1) {
                return new OsvCallFailure(FailureReason::Unparseable, 'A query result names a vulnerability without a usable id.');
            }

            $modified = $vuln['modified'] ?? '';
            $references[] = new OsvVulnerabilityReference($id, is_string($modified) ? $modified : '');
        }

        $nextPageToken = $result['next_page_token'] ?? '';

        return [
            'vulns' => $references,
            'nextPageToken' => is_string($nextPageToken) ? $nextPageToken : '',
        ];
    }

    /**
     * @return array<string, mixed>|OsvCallFailure
     */
    private function send(RequestInterface $request): array|OsvCallFailure
    {
        try {
            $response = $this->httpClient->sendRequest($this->userAgent->applyTo($request));
        } catch (ClientExceptionInterface $exception) {
            $this->logger->warning('OSV request failed.', ['exception' => $exception]);

            return new OsvCallFailure(
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
            return new OsvCallFailure(FailureReason::Unparseable, $exception->getMessage());
        } catch (ResponseBodyUnreadable $exception) {
            $this->logger->warning('OSV response could not be read.', ['message' => $exception->getMessage()]);

            return new OsvCallFailure(
                $this->failureClassifier->reasonForUnreadableBody($exception),
                $exception->getMessage(),
            );
        } catch (\JsonException $exception) {
            return new OsvCallFailure(FailureReason::Unparseable, 'The response is not JSON: ' . $exception->getMessage());
        }

        if (!is_array($decoded) || ($decoded !== [] && array_is_list($decoded))) {
            return new OsvCallFailure(FailureReason::Unparseable, 'The response is not a JSON object.');
        }

        return $this->stringKeyed($decoded);
    }

    private function failureForStatus(RequestInterface $request, ResponseInterface $response): OsvCallFailure
    {
        $status = $response->getStatusCode();
        $reason = $this->failureClassifier->reasonForStatus($status);

        return new OsvCallFailure(
            reason: $reason,
            detail: sprintf('OSV answered %d to %s %s.', $status, $request->getMethod(), $request->getUri()->getPath()),
            retryAfterSeconds: $reason === FailureReason::RateLimited
                ? $this->failureClassifier->retryAfterSeconds($response)
                : null,
        );
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
