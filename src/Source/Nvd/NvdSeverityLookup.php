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

use mteu\AdvisoryMatcher\Advisory\Nvd\NvdSeverityReader;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Source\Http\BoundedBodyReader;
use mteu\AdvisoryMatcher\Source\Http\HttpFailureClassifier;
use mteu\AdvisoryMatcher\Source\Http\UserAgent;
use mteu\AdvisoryMatcher\Source\SeverityLookup;
use mteu\AdvisoryMatcher\Source\SourceFailure;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final readonly class NvdSeverityLookup implements SeverityLookup
{
    private NvdApi $api;

    private NvdSeverityReader $reader;

    public function __construct(
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        #[\SensitiveParameter]
        string $apiKey = '',
        LoggerInterface $logger = new NullLogger(),
        string $userAgent = UserAgent::LIBRARY_DEFAULT,
        string $endpoint = 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        BoundedBodyReader $bodyReader = new BoundedBodyReader(),
        HttpFailureClassifier $failureClassifier = new HttpFailureClassifier(),
    ) {
        $this->reader = new NvdSeverityReader();
        $this->api = new NvdApi(
            $httpClient,
            $requestFactory,
            $bodyReader,
            $failureClassifier,
            $logger,
            $endpoint,
            trim($apiKey),
            new UserAgent($userAgent),
        );
    }

    public function severityForCve(string $cveId): Severity|SourceFailure
    {
        $record = $this->api->findVulnerabilityByCveId($cveId);

        if ($record instanceof SourceFailure) {
            return $record;
        }

        return $this->reader->severityOf($record);
    }

    public function storedSeveritiesForCves(array $cveIds): array
    {
        return [];
    }
}
