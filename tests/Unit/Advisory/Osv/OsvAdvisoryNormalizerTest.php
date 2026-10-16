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

namespace mteu\AdvisoryMatcher\Tests\Unit\Advisory\Osv;

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Tests\Unit\Advisory\AdvisoryBuilder;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Advisory\AdvisoryMatcher;
use mteu\AdvisoryMatcher\Advisory\MatchResult;
use mteu\AdvisoryMatcher\Advisory\Osv\OsvAdvisoryNormalizer;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Tests\Unit\Clock\FrozenClock;
use mteu\AdvisoryMatcher\Version\LenientVersionMatcher;
use mteu\AdvisoryMatcher\Version\VersionConstraintMatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(OsvAdvisoryNormalizer::class)]
final class OsvAdvisoryNormalizerTest extends TestCase
{
    private const string FROZEN_NOW = '2026-09-16T12:00:00+00:00';

    private OsvAdvisoryNormalizer $normalizer;

    protected function setUp(): void
    {
        $this->normalizer = new OsvAdvisoryNormalizer(FrozenClock::at(self::FROZEN_NOW));
    }

    #[Test]
    public function mapsACompleteRecordOntoAnAdvisory(): void
    {
        $advisory = $this->normalizer->normalize(
            [
                'id' => 'GHSA-aaaa-bbbb-cccc',
                'summary' => 'Prototype pollution',
                'published' => '2026-03-01T09:30:00Z',
                'aliases' => ['CVE-2026-1234'],
                'references' => [['url' => 'https://example.invalid/advisory']],
                'database_specific' => ['severity' => 'HIGH'],
            ],
            PackageUrl::fromPackageName('npm', 'acme/widget'),
            ['ranges' => [['events' => [['introduced' => '1.0.0'], ['fixed' => '1.6.0']]]]],
        );

        self::assertSame('OSV-GHSA-aaaa-bbbb-cccc', $advisory->advisoryId);
        self::assertSame('acme/widget', $advisory->packageName);
        self::assertSame(Ecosystem::Npm, $advisory->ecosystem);
        self::assertSame('Prototype pollution', $advisory->title);
        self::assertSame('https://example.invalid/advisory', $advisory->link);
        self::assertSame('CVE-2026-1234', $advisory->cve);
        self::assertSame('>=1.0.0,<1.6.0', $advisory->affectedVersions->toComposerConstraint());
        self::assertSame('1.6.0', $advisory->firstPatchedVersion);
        self::assertSame('2026-03-01T09:30:00+00:00', $advisory->reportedAt->format(\DateTimeInterface::ATOM));
        self::assertSame(Severity::High, $advisory->severity);
        self::assertCount(1, $advisory->references);
        self::assertSame('OSV', $advisory->references[0]->name);
        self::assertSame('GHSA-aaaa-bbbb-cccc', $advisory->references[0]->remoteId);
    }

    /**
     * @param array<string, mixed> $affected
     */
    #[Test]
    #[DataProvider('versionRangeProvider')]
    public function foldsRangeEventsIntoVersionRanges(array $affected, string $expected): void
    {
        self::assertSame($expected, $this->normalize($affected)->affectedVersions->toComposerConstraint());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function versionRangeProvider(): iterable
    {
        yield 'introduced and fixed' => [
            ['ranges' => [['events' => [['introduced' => '1.0.0'], ['fixed' => '1.6.0']]]]],
            '>=1.0.0,<1.6.0',
        ];
        yield 'introduced only' => [
            ['ranges' => [['events' => [['introduced' => '1.0.0']]]]],
            '>=1.0.0',
        ];
        yield 'fixed only' => [
            ['ranges' => [['events' => [['fixed' => '1.6.0']]]]],
            '<1.6.0',
        ];
        yield 'several branches are joined with or' => [
            ['ranges' => [
                ['events' => [['introduced' => '1.0.0'], ['fixed' => '1.6.0']]],
                ['events' => [['introduced' => '2.0.0'], ['fixed' => '2.1.0']]],
            ]],
            '>=1.0.0,<1.6.0 || >=2.0.0,<2.1.0',
        ];
        yield 'several pairs in one range are joined with or' => [
            ['ranges' => [['type' => 'ECOSYSTEM', 'events' => [
                ['introduced' => '1.0'],
                ['fixed' => '1.5'],
                ['introduced' => '2.0'],
                ['fixed' => '2.3'],
            ]]]],
            '>=1.0,<1.5 || >=2.0,<2.3',
        ];
        yield 'open-ended introduced after a closed pair' => [
            ['ranges' => [['events' => [['introduced' => '1.0'], ['fixed' => '1.5'], ['introduced' => '2.0']]]]],
            '>=1.0,<1.5 || >=2.0',
        ];
        yield 'last_affected closes the range inclusively' => [
            ['ranges' => [['events' => [['introduced' => '0'], ['last_affected' => '1.4.2']]]]],
            '>=0,<=1.4.2',
        ];
        yield 'last_affected only' => [
            ['ranges' => [['events' => [['last_affected' => '1.4.2']]]]],
            '<=1.4.2',
        ];
        yield 'a repeated introduced keeps the earliest open' => [
            ['ranges' => [['events' => [['introduced' => '1.0'], ['introduced' => '1.2'], ['fixed' => '1.5']]]]],
            '>=1.0,<1.5',
        ];
        yield 'a git range next to an ecosystem range is skipped' => [
            ['ranges' => [
                ['type' => 'GIT', 'repo' => 'https://example.invalid/repo.git', 'events' => [
                    ['introduced' => '0'],
                    ['fixed' => 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2'],
                ]],
                ['type' => 'ECOSYSTEM', 'events' => [['introduced' => '1.0.0'], ['fixed' => '1.6.0']]],
            ]],
            '>=1.0.0,<1.6.0',
        ];
        yield 'a git range alone yields nothing' => [
            ['ranges' => [['type' => 'GIT', 'events' => [['introduced' => '0'], ['fixed' => 'a1b2c3d4']]]]],
            '',
        ];
        yield 'limit is ignored' => [
            ['ranges' => [['events' => [['introduced' => '1.0'], ['limit' => '1.9'], ['fixed' => '1.5']]]]],
            '>=1.0,<1.5',
        ];
        yield 'no ranges at all' => [[], ''];
        yield 'ranges present but empty' => [['ranges' => []], ''];
        yield 'range without events' => [['ranges' => [['type' => 'SEMVER']]], ''];
        yield 'events carrying nothing usable' => [['ranges' => [['events' => [['limit' => '*']]]]], ''];
    }

    /**
     * @param list<array<string, string>> $events
     */
    #[Test]
    #[DataProvider('affectedVersionProvider')]
    public function convertedRangesCoverExactlyTheDeclaredVersions(
        array $events,
        string $version,
        MatchResult $expected,
    ): void {
        $matcher = new AdvisoryMatcher(new VersionConstraintMatcher(), new LenientVersionMatcher());
        $advisory = $this->normalize(['ranges' => [['type' => 'ECOSYSTEM', 'events' => $events]]]);

        self::assertSame($expected, $matcher->match($advisory, $version));
    }

    /**
     * @return iterable<string, array{list<array<string, string>>, string, MatchResult}>
     */
    public static function affectedVersionProvider(): iterable
    {
        $twoPairs = [['introduced' => '1.0'], ['fixed' => '1.5'], ['introduced' => '2.0'], ['fixed' => '2.3']];
        yield 'two pairs: inside the first' => [$twoPairs, '1.2', MatchResult::Affected];
        yield 'two pairs: between them' => [$twoPairs, '1.7', MatchResult::NotAffected];
        yield 'two pairs: inside the second' => [$twoPairs, '2.1', MatchResult::Affected];
        yield 'two pairs: after both' => [$twoPairs, '3.0', MatchResult::NotAffected];

        $lastAffected = [['introduced' => '0'], ['last_affected' => '1.4.2']];
        yield 'last_affected: the last affected release itself' => [$lastAffected, '1.4.2', MatchResult::Affected];
        yield 'last_affected: the release after it' => [$lastAffected, '1.4.3', MatchResult::NotAffected];
    }

    #[Test]
    public function takesTheLowestFixedVersionAcrossBranches(): void
    {
        $advisory = $this->normalize(['ranges' => [
            ['events' => [['introduced' => '2.0.0'], ['fixed' => '2.1.0']]],
            ['events' => [['introduced' => '1.0.0'], ['fixed' => '1.6.0']]],
        ]]);

        self::assertSame('1.6.0', $advisory->firstPatchedVersion);
    }

    #[Test]
    public function namesNoFixedVersionWhenNoRangeCloses(): void
    {
        self::assertSame(
            '',
            $this->normalize(['ranges' => [['events' => [['introduced' => '1.0.0']]]]])->firstPatchedVersion,
        );
    }

    #[Test]
    public function namesNoFixedVersionWhenTheRangeEndsAtALastAffectedRelease(): void
    {
        self::assertSame(
            '',
            $this->normalize(['ranges' => [['events' => [['introduced' => '0'], ['last_affected' => '1.4.2']]]]])
                ->firstPatchedVersion,
        );
    }

    #[Test]
    public function neverOffersACommitHashAsTheFixedVersion(): void
    {
        $advisory = $this->normalize(['ranges' => [
            ['type' => 'GIT', 'events' => [['introduced' => '0'], ['fixed' => '0a1b2c3d4e5f']]],
            ['type' => 'ECOSYSTEM', 'events' => [['introduced' => '1.0.0'], ['fixed' => '1.6.0']]],
        ]]);

        self::assertSame('1.6.0', $advisory->firstPatchedVersion);
    }

    #[Test]
    #[DataProvider('severityProvider')]
    public function readsSeverityFromWhicheverPlaceTheRecordStatesIt(
        mixed $databaseSpecific,
        mixed $severityEntries,
        Severity $expected,
    ): void {
        $vulnerability = ['id' => 'OSV-1'];
        if ($databaseSpecific !== null) {
            $vulnerability['database_specific'] = $databaseSpecific;
        }
        if ($severityEntries !== null) {
            $vulnerability['severity'] = $severityEntries;
        }

        $advisory = $this->normalizer->normalize($vulnerability, PackageUrl::fromPackageName('npm', 'acme/widget'), []);

        self::assertSame($expected, $advisory->severity);
    }

    /**
     * @return iterable<string, array{mixed, mixed, Severity}>
     */
    public static function severityProvider(): iterable
    {
        yield 'label wins over score' => [
            ['severity' => 'critical'],
            [['score' => 4.1]],
            Severity::Critical,
        ];
        yield 'label is case insensitive' => [['severity' => 'HIGH'], null, Severity::High];
        yield 'moderate is the middle band' => [['severity' => 'moderate'], null, Severity::Medium];
        yield 'info is the lowest band' => [['severity' => 'info'], null, Severity::Low];
        yield 'cvss critical' => [null, [['score' => 9.8]], Severity::Critical];
        yield 'cvss high' => [null, [['score' => 7.0]], Severity::High];
        yield 'cvss medium' => [null, [['score' => 4.0]], Severity::Medium];
        yield 'cvss low' => [null, [['score' => 3.9]], Severity::Low];
        yield 'cvss score given as a string' => [null, [['score' => '9.1']], Severity::Critical];

        // OSV states CVSS as a vector string, which is what the schema defines
        // `score` to be.
        yield 'cvss 3.1 vector scoring 10.0' => [
            null,
            [['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H']],
            Severity::Critical,
        ];
        yield 'cvss 3.1 vector scoring 6.1' => [
            null,
            [['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N']],
            Severity::Medium,
        ];
        yield 'cvss 3.0 vector scoring 7.5' => [
            null,
            [['type' => 'CVSS_V3', 'score' => 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H']],
            Severity::High,
        ];
        yield 'a v4 vector is skipped for a v3 one' => [
            null,
            [
                ['type' => 'CVSS_V4', 'score' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
                ['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'],
            ],
            Severity::High,
        ];
        yield 'an unrecognised label falls to the vector' => [
            ['severity' => 'catastrophic'],
            [['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H']],
            Severity::Critical,
        ];

        // A record stating no usable severity is unknown: filed as low, it
        // would fall below a raised minimum-severity threshold.
        yield 'neither stated' => [null, null, Severity::Unknown];
        yield 'severity entries carry no score' => [null, [['type' => 'CVSS_V3']], Severity::Unknown];
        yield 'a v4 vector alone' => [
            null,
            [['type' => 'CVSS_V4', 'score' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N']],
            Severity::Unknown,
        ];
        yield 'a malformed vector' => [null, [['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:X']], Severity::Unknown];
        yield 'unrecognised label and nothing else' => [['severity' => 'catastrophic'], null, Severity::Unknown];
    }

    #[Test]
    #[DataProvider('linkProvider')]
    public function prefersTheFirstSafeReferenceUrl(mixed $references, string $expected): void
    {
        $vulnerability = ['id' => 'GHSA-aaaa-bbbb-cccc'];
        if ($references !== null) {
            $vulnerability['references'] = $references;
        }

        $advisory = $this->normalizer->normalize($vulnerability, PackageUrl::fromPackageName('npm', 'acme/widget'), []);

        self::assertSame($expected, $advisory->link);
    }

    /**
     * @return iterable<string, array{mixed, string}>
     */
    public static function linkProvider(): iterable
    {
        $canonical = 'https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc';

        yield 'https reference' => [[['url' => 'https://example.invalid/a']], 'https://example.invalid/a'];
        yield 'http reference' => [[['url' => 'http://example.invalid/a']], 'http://example.invalid/a'];
        yield 'first of several wins' => [
            [['url' => 'https://example.invalid/a'], ['url' => 'https://example.invalid/b']],
            'https://example.invalid/a',
        ];
        yield 'surrounding whitespace is trimmed' => [
            [['url' => '  https://example.invalid/a  ']],
            'https://example.invalid/a',
        ];
        yield 'no references' => [null, $canonical];
        yield 'references carry no url' => [[['type' => 'WEB']], $canonical];

        // This string reaches a template as a link target, so a scheme that
        // executes must never survive the feed.
        yield 'javascript uri is rejected' => [[['url' => 'javascript:alert(1)']], $canonical];
        yield 'data uri is rejected' => [[['url' => 'data:text/html,<script>']], $canonical];
        yield 'unsafe url is skipped in favour of a later safe one' => [
            [['url' => 'javascript:alert(1)'], ['url' => 'https://example.invalid/a']],
            'https://example.invalid/a',
        ];
    }

    #[Test]
    #[DataProvider('titleProvider')]
    public function fallsBackThroughSummaryAndDetailsForATitle(
        mixed $summary,
        mixed $details,
        string $expected,
    ): void {
        $vulnerability = ['id' => 'OSV-1'];
        if ($summary !== null) {
            $vulnerability['summary'] = $summary;
        }
        if ($details !== null) {
            $vulnerability['details'] = $details;
        }

        self::assertSame(
            $expected,
            $this->normalizer->normalize($vulnerability, PackageUrl::fromPackageName('npm', 'acme/widget'), [])->title,
        );
    }

    /**
     * @return iterable<string, array{mixed, mixed, string}>
     */
    public static function titleProvider(): iterable
    {
        yield 'summary wins' => ['A summary', 'Some details', 'A summary'];
        yield 'details when no summary' => [null, 'Some details', 'Some details'];
        yield 'details when summary is empty' => ['', 'Some details', 'Some details'];
        yield 'fallback when neither' => [null, null, 'Security vulnerability'];
        yield 'fallback when both empty' => ['', '', 'Security vulnerability'];
    }

    #[Test]
    #[DataProvider('cveProvider')]
    public function takesTheCveFromTheAliases(mixed $aliases, string $expected): void
    {
        $vulnerability = ['id' => 'OSV-1'];
        if ($aliases !== null) {
            $vulnerability['aliases'] = $aliases;
        }

        self::assertSame(
            $expected,
            $this->normalizer->normalize($vulnerability, PackageUrl::fromPackageName('npm', 'acme/widget'), [])->cve,
        );
    }

    /**
     * @return iterable<string, array{mixed, string}>
     */
    public static function cveProvider(): iterable
    {
        yield 'single cve' => [['CVE-2026-1234'], 'CVE-2026-1234'];
        yield 'cve among other aliases' => [['GHSA-aaaa-bbbb-cccc', 'CVE-2026-1234'], 'CVE-2026-1234'];
        yield 'no cve among aliases' => [['GHSA-aaaa-bbbb-cccc'], ''];
        yield 'no aliases' => [null, ''];
    }

    #[Test]
    public function datesARecordToNowWhenItPublishesNoUsableDate(): void
    {
        foreach ([null, '', 'not a date at all'] as $published) {
            $vulnerability = ['id' => 'OSV-1'];
            if ($published !== null) {
                $vulnerability['published'] = $published;
            }

            $advisory = $this->normalizer->normalize($vulnerability, PackageUrl::fromPackageName('npm', 'acme/widget'), []);

            self::assertSame(
                self::FROZEN_NOW,
                $advisory->reportedAt->format(\DateTimeInterface::ATOM),
                sprintf('published: %s', var_export($published, true)),
            );
        }
    }

    #[Test]
    public function namesTheRecordEvenWhenItCarriesNoId(): void
    {
        $advisory = $this->normalizer->normalize([], PackageUrl::fromPackageName('npm', 'acme/widget'), []);

        self::assertSame('OSV-OSV-unknown', $advisory->advisoryId);
    }

    #[Test]
    public function survivesAPayloadWhoseEveryFieldIsTheWrongShape(): void
    {
        $advisory = $this->normalizer->normalize(
            [
                'id' => 42,
                'summary' => ['not', 'a', 'string'],
                'details' => 7,
                'published' => 1234,
                'aliases' => 'CVE-2026-1234',
                'references' => 'https://example.invalid',
                'database_specific' => 'high',
                'severity' => 'critical',
            ],
            PackageUrl::fromPackageName('npm', 'acme/widget'),
            ['ranges' => 'not an array'],
        );

        self::assertSame('OSV-OSV-unknown', $advisory->advisoryId);
        self::assertSame('Security vulnerability', $advisory->title);
        self::assertSame('', $advisory->cve);
        self::assertSame('', $advisory->affectedVersions->toComposerConstraint());
        self::assertSame('https://osv.dev/vulnerability/OSV-unknown', $advisory->link);
        self::assertSame(Severity::Unknown, $advisory->severity);
        self::assertSame(self::FROZEN_NOW, $advisory->reportedAt->format(\DateTimeInterface::ATOM));
    }

    #[Test]
    #[DataProvider('ecosystemProvider')]
    public function filesTheAdvisoryUnderTheEcosystemItWasAskedFor(Ecosystem $ecosystem): void
    {
        $advisory = $this->normalizer->normalize(['id' => 'OSV-1'], AdvisoryBuilder::packageUrlOf($ecosystem, 'acme/widget'), []);

        self::assertSame($ecosystem, $advisory->ecosystem);
    }

    /**
     * @return iterable<string, array{Ecosystem}>
     */
    public static function ecosystemProvider(): iterable
    {
        yield 'npm' => [Ecosystem::Npm];
        yield 'composer' => [Ecosystem::Composer];
    }

    /**
     * @param array<string, mixed> $affected
     */
    private function normalize(array $affected): Advisory
    {
        return $this->normalizer->normalize(['id' => 'OSV-1'], PackageUrl::fromPackageName('npm', 'acme/widget'), $affected);
    }
}
