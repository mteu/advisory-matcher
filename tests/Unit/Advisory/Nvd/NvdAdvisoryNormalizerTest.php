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

namespace mteu\AdvisoryMatcher\Tests\Unit\Advisory\Nvd;

use mteu\AdvisoryMatcher\Advisory\Advisory;
use mteu\AdvisoryMatcher\Advisory\AdvisoryMatcher;
use mteu\AdvisoryMatcher\Advisory\MatchResult;
use mteu\AdvisoryMatcher\Advisory\Nvd\NvdAdvisoryNormalizer;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\CpeIdentity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Tests\Unit\Clock\FrozenClock;
use mteu\AdvisoryMatcher\Version\LenientVersionMatcher;
use mteu\AdvisoryMatcher\Version\VersionConstraintMatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(NvdAdvisoryNormalizer::class)]
final class NvdAdvisoryNormalizerTest extends TestCase
{
    private const string NOW = '2026-09-24T12:00:00+00:00';

    #[Test]
    public function theAdvisoryIsFiledUnderTheAskedNameWithItsCveSourceAndNvdLink(): void
    {
        $advisory = $this->normalize(self::cveRecord());

        self::assertSame('NVD-CVE-2025-1217', $advisory->advisoryId);
        self::assertSame('CVE-2025-1217', $advisory->cve);
        self::assertSame('php', $advisory->packageName);
        self::assertSame(Ecosystem::Php, $advisory->ecosystem);
        self::assertSame('https://nvd.nist.gov/vuln/detail/CVE-2025-1217', $advisory->link);
        self::assertSame('NVD', $advisory->references[0]->name);
        self::assertSame('CVE-2025-1217', $advisory->references[0]->remoteId);
    }

    #[Test]
    public function thePublicationDateIsReadAsUtc(): void
    {
        $advisory = $this->normalize(self::cveRecord());

        self::assertSame('2025-03-29T06:15:36+00:00', $advisory->reportedAt->format(\DateTimeInterface::ATOM));
    }

    #[Test]
    public function aRecordWithoutAUsableDateIsDatedToWhenItWasRead(): void
    {
        $record = self::cveRecord();
        $record['published'] = 'not a date';

        self::assertSame(self::NOW, $this->normalize($record)->reportedAt->format(\DateTimeInterface::ATOM));
    }

    #[Test]
    public function theTitleIsTheEnglishDescriptionCutToOneLine(): void
    {
        $record = self::cveRecord();

        self::assertSame(
            'The header parsing of the http request module has a flaw.',
            $this->normalize($record)->title,
        );

        $record['descriptions'] = [['lang' => 'en', 'value' => str_repeat('ä', 130)]];

        self::assertSame(str_repeat('ä', 120) . '...', $this->normalize($record)->title);
    }

    #[Test]
    public function aRecordWithoutAnEnglishDescriptionStillHasATitle(): void
    {
        $record = self::cveRecord();
        $record['descriptions'] = [['lang' => 'es', 'value' => 'Solo en español.']];

        self::assertSame('Security vulnerability', $this->normalize($record)->title);
    }

    #[Test]
    public function versionRangesComeOnlyFromThisProductsVulnerableMatches(): void
    {
        self::assertSame(
            '>=8.1.0,<8.1.32 || >=8.3.0,<8.3.19',
            $this->normalize(self::cveRecord())->affectedVersions->toComposerConstraint(),
        );
    }

    #[Test]
    public function theFirstPatchedVersionIsTheNearestReleaseAboveTheInstalledOne(): void
    {
        $advisory = $this->normalize(self::cveRecord());

        self::assertTrue($advisory->hasRemediation());
        self::assertSame('8.3.19', $advisory->firstPatchedVersion);
    }

    #[Test]
    public function withoutAnInstalledReleaseTheLowestFixIsNamed(): void
    {
        self::assertSame('8.1.32', $this->normalize(self::cveRecord(), installedRelease: '')->firstPatchedVersion);
    }

    #[Test]
    public function whenNoFixLiesAboveTheInstalledReleaseTheLowestStillStands(): void
    {
        self::assertSame('8.1.32', $this->normalize(self::cveRecord(), installedRelease: '9.0.0')->firstPatchedVersion);
    }

    #[Test]
    public function aMatchWithoutVersionBoundsIsKeptAsCoveringEveryVersion(): void
    {
        $record = self::withMatches(['cpe:2.3:a:php:php:*:*:*:*:*:*:*:*']);

        $advisory = $this->normalize($record);

        self::assertSame('*', $advisory->affectedVersions->toComposerConstraint());
        self::assertFalse($advisory->hasRemediation());
    }

    #[Test]
    public function anExactVersionMatchBecomesAnExactVersionRange(): void
    {
        self::assertSame(
            '8.5.0',
            $this->normalize(self::withMatches(['cpe:2.3:a:php:php:8.5.0:*:*:*:*:*:*:*']))->affectedVersions->toComposerConstraint(),
        );
    }

    #[Test]
    public function aRecordConfiguringNothingForThisProductNamesNoRange(): void
    {
        $record = self::cveRecord();
        $record['configurations'] = 'not a list';

        self::assertSame('', $this->normalize($record)->affectedVersions->toComposerConstraint());
    }

    #[Test]
    public function theRangesMatchTheVersionNvdWasAskedAbout(): void
    {
        $matcher = new AdvisoryMatcher(new VersionConstraintMatcher(), new LenientVersionMatcher());
        $advisory = $this->normalize(self::cveRecord());

        self::assertSame(MatchResult::Affected, $matcher->match($advisory, '8.3.14'));
        self::assertSame(MatchResult::NotAffected, $matcher->match($advisory, '8.3.19'));
    }

    #[Test]
    public function theBandIsReadFromThePrimaryMetricOfTheNewestCvssVersion(): void
    {
        self::assertSame(Severity::High, $this->normalize(self::cveRecord())->severity);
    }

    #[Test]
    public function cvssV4WinsOverV31(): void
    {
        $record = self::cveRecord();
        $record['metrics'] = [
            'cvssMetricV31' => [['type' => 'Primary', 'cvssData' => ['baseScore' => 7.5, 'baseSeverity' => 'HIGH']]],
            'cvssMetricV40' => [['type' => 'Primary', 'cvssData' => ['baseScore' => 9.3, 'baseSeverity' => 'CRITICAL']]],
        ];

        self::assertSame(Severity::Critical, $this->normalize($record)->severity);
    }

    #[Test]
    public function cvssV31WinsOverV2(): void
    {
        $v2 = ['cvssMetricV2' => [['type' => 'Primary', 'cvssData' => ['baseScore' => 2.6], 'baseSeverity' => 'LOW']]];
        $record = self::cveRecord();

        $record['metrics'] = $v2;
        self::assertSame(Severity::Low, $this->normalize($record)->severity, 'v2 alone is read.');

        $record['metrics'] = $v2 + [
            'cvssMetricV31' => [['type' => 'Primary', 'cvssData' => ['baseScore' => 7.5, 'baseSeverity' => 'HIGH']]],
        ];
        self::assertSame(Severity::High, $this->normalize($record)->severity);
    }

    #[Test]
    public function withoutAPrimaryMetricTheFirstOneIsRead(): void
    {
        $record = self::cveRecord();
        $record['metrics'] = ['cvssMetricV31' => [
            ['type' => 'Secondary', 'cvssData' => ['baseSeverity' => 'MEDIUM']],
            ['type' => 'Secondary', 'cvssData' => ['baseSeverity' => 'CRITICAL']],
        ]];

        self::assertSame(Severity::Medium, $this->normalize($record)->severity);
    }

    /**
     * @param array<string, mixed> $metrics
     */
    #[Test]
    #[DataProvider('metricProvider')]
    public function severityFollowsTheStatedBandThenTheScoreThenUnknown(array $metrics, Severity $expected): void
    {
        $record = self::cveRecord();
        $record['metrics'] = $metrics;

        self::assertSame($expected, $this->normalize($record)->severity);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, Severity}>
     */
    public static function metricProvider(): iterable
    {
        $v2 = static fn (array $metric): array => ['cvssMetricV2' => [['type' => 'Primary'] + $metric]];

        yield 'score 9.0 is critical' => [$v2(['cvssData' => ['baseScore' => 9.0]]), Severity::Critical];
        yield 'score 7.0 is high' => [$v2(['cvssData' => ['baseScore' => 7.0]]), Severity::High];
        yield 'score 4.0 is medium' => [$v2(['cvssData' => ['baseScore' => 4.0]]), Severity::Medium];
        yield 'score 3.9 is low' => [$v2(['cvssData' => ['baseScore' => 3.9]]), Severity::Low];
        yield 'a numeric string score' => [$v2(['cvssData' => ['baseScore' => '9.8']]), Severity::Critical];
        yield 'v2 states its band beside the score data' => [
            $v2(['cvssData' => ['baseScore' => 9.3], 'baseSeverity' => 'MEDIUM']),
            Severity::Medium,
        ];
        yield 'a stated band wins over the score' => [
            $v2(['cvssData' => ['baseScore' => 9.8, 'baseSeverity' => 'LOW']]),
            Severity::Low,
        ];
        yield 'NONE is low' => [$v2(['cvssData' => ['baseSeverity' => 'NONE']]), Severity::Low];
        yield 'an unknown label with no score is unknown' => [
            $v2(['cvssData' => ['baseSeverity' => 'SEVERE']]),
            Severity::Unknown,
        ];
        yield 'an unknown label falls to the score' => [
            $v2(['cvssData' => ['baseSeverity' => 'SEVERE', 'baseScore' => 7.1]]),
            Severity::High,
        ];
        yield 'a blank label falls to the score' => [
            $v2(['cvssData' => ['baseSeverity' => ' ', 'baseScore' => 7.1]]),
            Severity::High,
        ];
        yield 'no metrics at all is unknown' => [[], Severity::Unknown];
        yield 'an empty block is skipped' => [['cvssMetricV40' => [], ...$v2(['cvssData' => ['baseScore' => 9.1]])], Severity::Critical];
        yield 'a metric with neither band nor score is skipped' => [
            ['cvssMetricV31' => [['type' => 'Primary', 'cvssData' => []]], ...$v2(['cvssData' => ['baseScore' => 7.2]])],
            Severity::High,
        ];
        yield 'nothing usable anywhere is unknown' => [['cvssMetricV31' => [['type' => 'Primary']]], Severity::Unknown];
    }

    #[Test]
    public function anIdThatIsNotACveCarriesNoCve(): void
    {
        $record = self::cveRecord();
        $record['id'] = 'GHSA-xxxx';

        $advisory = $this->normalize($record);

        self::assertSame('', $advisory->cve);
        self::assertSame('NVD-GHSA-xxxx', $advisory->advisoryId);
    }

    #[Test]
    public function aRecordWithoutAnIdStillNormalises(): void
    {
        $record = self::cveRecord();
        unset($record['id']);

        self::assertSame('NVD-CVE-unknown', $this->normalize($record)->advisoryId);
    }

    /**
     * @param array<string, mixed> $record
     */
    private function normalize(array $record, string $installedRelease = '8.3.14'): Advisory
    {
        return (new NvdAdvisoryNormalizer(FrozenClock::at(self::NOW)))
            ->normalize($record, 'php', CpeIdentity::application('php', 'php'), $installedRelease);
    }

    /**
     * @param list<string> $criteria
     * @return array<string, mixed>
     */
    private static function withMatches(array $criteria): array
    {
        $record = self::cveRecord();
        $record['configurations'] = [['nodes' => [['cpeMatch' => array_map(
            static fn (string $criterion): array => ['vulnerable' => true, 'criteria' => $criterion],
            $criteria,
        )]]]];

        return $record;
    }

    /**
     * @return array<string, mixed>
     */
    private static function cveRecord(): array
    {
        $decoded = json_decode((string)file_get_contents(__DIR__ . '/Fixtures/CVE-2025-1217.json'), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        $record = [];

        foreach ($decoded as $key => $value) {
            self::assertIsString($key);
            $record[$key] = $value;
        }

        return $record;
    }
}
