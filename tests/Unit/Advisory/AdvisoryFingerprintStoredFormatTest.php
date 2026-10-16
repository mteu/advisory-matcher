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

namespace mteu\AdvisoryMatcher\Tests\Unit\Advisory;

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\AdvisoryFingerprint;
use mteu\AdvisoryMatcher\Advisory\AdvisoryReference;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Consumers store these strings in their databases and in VEX assessments.
 * A change to any of them makes stored assessments stop matching, and their
 * findings come back. Change an expectation here only together with a
 * migration for the stored data.
 */
#[CoversClass(AdvisoryFingerprint::class)]
final class AdvisoryFingerprintStoredFormatTest extends TestCase
{
    /**
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('storedIdentitiesProvider')]
    public function keepsTheIdentitiesConsumersHaveStored(Advisory $advisory, array $expected): void
    {
        self::assertSame($expected, AdvisoryFingerprint::identitiesOf($advisory));
    }

    /**
     * @return iterable<string, array{Advisory, list<string>}>
     */
    public static function storedIdentitiesProvider(): iterable
    {
        yield 'Composer package' => [
            AdvisoryBuilder::build(
                advisoryId: 'PKSA-1111-2222-3333',
                packageName: 'symfony/http-kernel',
                ecosystem: Ecosystem::Composer,
                remoteId: 'GHSA-aaaa-bbbb-cccc',
                cve: 'CVE-2026-1234',
            ),
            [
                'composer|symfony/http-kernel|cve|CVE-2026-1234',
                'composer|symfony/http-kernel|ghsa|GHSA-AAAA-BBBB-CCCC',
                'composer|symfony/http-kernel|id|PKSA-1111-2222-3333',
            ],
        ];

        yield 'npm package' => [
            AdvisoryBuilder::build(
                advisoryId: 'OSV-GHSA-dddd-eeee-ffff',
                packageName: 'lodash',
                ecosystem: Ecosystem::Npm,
                cve: 'CVE-2026-5678',
            ),
            [
                'npm|lodash|cve|CVE-2026-5678',
                'npm|lodash|ghsa|GHSA-DDDD-EEEE-FFFF',
                'npm|lodash|id|OSV-GHSA-dddd-eeee-ffff',
            ],
        ];

        yield 'PHP runtime' => [
            AdvisoryBuilder::build(
                advisoryId: 'NVD-CVE-2025-1217',
                packageName: 'php',
                ecosystem: Ecosystem::Php,
                cve: 'CVE-2025-1217',
                references: [new AdvisoryReference('NVD', 'CVE-2025-1217')],
            ),
            [
                'php|php|cve|CVE-2025-1217',
                'php|php|id|NVD-CVE-2025-1217',
            ],
        ];

        yield 'scoped npm package' => [
            AdvisoryBuilder::build(
                advisoryId: 'OSV-GHSA-gggg-hhhh-iiii',
                packageName: '@babel/traverse',
                ecosystem: Ecosystem::Npm,
            ),
            [
                'npm|@babel/traverse|ghsa|GHSA-GGGG-HHHH-IIII',
                'npm|@babel/traverse|id|OSV-GHSA-gggg-hhhh-iiii',
            ],
        ];

        yield 'advisory nothing names' => [
            AdvisoryBuilder::build(
                advisoryId: '',
                packageName: 'vendor/package',
                title: 'A vulnerability',
                affectedVersions: '>=1.0.0,<1.6.0',
            ),
            [
                'composer|vendor/package|hash|ef6fb8f2bed7518d705e4226fcaa92ae',
            ],
        ];
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function packagesAndTheKeyTheyAreStoredUnder(): iterable
    {
        yield 'a Composer package' => ['pkg:composer/symfony/http-kernel', 'composer|symfony/http-kernel'];
        yield 'a Composer package in mixed case' => ['pkg:composer/Symfony/HTTP-Kernel', 'composer|symfony/http-kernel'];
        yield 'an npm package' => ['pkg:npm/lodash', 'npm|lodash'];
        yield 'a scoped npm package' => ['pkg:npm/@acme/widgets@2.1.0', 'npm|@acme/widgets'];
        yield 'a scoped npm package with an encoded scope' => ['pkg:npm/%40acme/widgets', 'npm|@acme/widgets'];
        yield 'an npm package published in mixed case' => ['pkg:npm/JSONStream', 'npm|JSONStream'];
        yield 'the PHP runtime' => ['pkg:generic/php', 'php|php'];
    }

    #[Test]
    #[DataProvider('packagesAndTheKeyTheyAreStoredUnder')]
    public function keepsThePackageKeyConsumersHaveStoredWhateverTheSpelling(string $purl, string $packageKey): void
    {
        self::assertSame(
            [
                $packageKey . '|cve|CVE-2026-1234',
                $packageKey . '|ghsa|GHSA-AAAA-BBBB-CCCC',
                $packageKey . '|id|PKSA-1111-2222-3333',
            ],
            AdvisoryFingerprint::identitiesOf(AdvisoryBuilder::onPackage(PackageUrl::fromString($purl))),
        );
    }
}
