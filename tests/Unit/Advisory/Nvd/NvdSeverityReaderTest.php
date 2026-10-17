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

use mteu\AdvisoryMatcher\Advisory\Nvd\NvdSeverityReader;
use mteu\AdvisoryMatcher\Advisory\Severity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(NvdSeverityReader::class)]
final class NvdSeverityReaderTest extends TestCase
{
    #[Test]
    public function theBandIsReadFromThePrimaryMetricOfTheNewestCvssVersion(): void
    {
        self::assertSame(Severity::High, $this->severityOf(self::fixtureMetrics()));
    }

    #[Test]
    public function cvssV4WinsOverV31(): void
    {
        self::assertSame(Severity::Critical, $this->severityOf([
            'cvssMetricV31' => [['type' => 'Primary', 'cvssData' => ['baseScore' => 7.5, 'baseSeverity' => 'HIGH']]],
            'cvssMetricV40' => [['type' => 'Primary', 'cvssData' => ['baseScore' => 9.3, 'baseSeverity' => 'CRITICAL']]],
        ]));
    }

    #[Test]
    public function cvssV31WinsOverV2(): void
    {
        $v2 = ['cvssMetricV2' => [['type' => 'Primary', 'cvssData' => ['baseScore' => 2.6], 'baseSeverity' => 'LOW']]];

        self::assertSame(Severity::Low, $this->severityOf($v2), 'v2 alone is read.');
        self::assertSame(Severity::High, $this->severityOf($v2 + [
            'cvssMetricV31' => [['type' => 'Primary', 'cvssData' => ['baseScore' => 7.5, 'baseSeverity' => 'HIGH']]],
        ]));
    }

    /**
     * @param array<string, mixed> $metrics
     */
    #[Test]
    #[DataProvider('versionOrderProvider')]
    public function theNewestCvssVersionPresentIsRead(array $metrics, Severity $expected): void
    {
        self::assertSame($expected, $this->severityOf($metrics));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, Severity}>
     */
    public static function versionOrderProvider(): iterable
    {
        $metric = static fn (string $band): array => [['type' => 'Primary', 'cvssData' => ['baseSeverity' => $band]]];

        yield 'v4.0 alone' => [['cvssMetricV40' => $metric('CRITICAL')], Severity::Critical];
        yield 'v3.1 alone' => [['cvssMetricV31' => $metric('HIGH')], Severity::High];
        yield 'v3.0 alone' => [['cvssMetricV30' => $metric('MEDIUM')], Severity::Medium];
        yield 'v2 alone' => [['cvssMetricV2' => $metric('LOW')], Severity::Low];
        yield 'v4.0 over v3.1' => [
            ['cvssMetricV31' => $metric('LOW'), 'cvssMetricV40' => $metric('CRITICAL')],
            Severity::Critical,
        ];
        yield 'v3.1 over v3.0' => [
            ['cvssMetricV30' => $metric('LOW'), 'cvssMetricV31' => $metric('HIGH')],
            Severity::High,
        ];
        yield 'v3.0 over v2' => [
            ['cvssMetricV2' => $metric('LOW'), 'cvssMetricV30' => $metric('MEDIUM')],
            Severity::Medium,
        ];
    }

    /**
     * @param list<mixed> $entries
     */
    #[Test]
    #[DataProvider('metricChoiceProvider')]
    public function thePrimaryMetricIsPreferredOverTheFirst(array $entries, Severity $expected): void
    {
        self::assertSame($expected, $this->severityOf(['cvssMetricV31' => $entries]));
    }

    /**
     * @return iterable<string, array{list<mixed>, Severity}>
     */
    public static function metricChoiceProvider(): iterable
    {
        $metric = static fn (string $type, string $band): array => ['type' => $type, 'cvssData' => ['baseSeverity' => $band]];

        yield 'a Primary listed after a Secondary' => [
            [$metric('Secondary', 'LOW'), $metric('Primary', 'CRITICAL')],
            Severity::Critical,
        ];
        yield 'without a Primary the first Secondary' => [
            [$metric('Secondary', 'MEDIUM'), $metric('Secondary', 'CRITICAL')],
            Severity::Medium,
        ];
        yield 'an entry that is no metric is passed over' => [
            ['not a metric', $metric('Secondary', 'HIGH')],
            Severity::High,
        ];
    }

    /**
     * @param array<string, mixed> $metrics
     */
    #[Test]
    #[DataProvider('metricProvider')]
    public function severityFollowsTheStatedBandThenTheScoreThenUnknown(array $metrics, Severity $expected): void
    {
        self::assertSame($expected, $this->severityOf($metrics));
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
        yield 'a score that is no number is unknown' => [$v2(['cvssData' => ['baseScore' => 'high']]), Severity::Unknown];
        yield 'v2 states its band beside the score data' => [
            $v2(['cvssData' => ['baseScore' => 9.3], 'baseSeverity' => 'MEDIUM']),
            Severity::Medium,
        ];
        yield 'a band beside score data that is no object' => [
            $v2(['cvssData' => 'not an object', 'baseSeverity' => 'HIGH']),
            Severity::High,
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
        yield 'a label that is no string falls to the score' => [
            $v2(['cvssData' => ['baseSeverity' => 3, 'baseScore' => 9.1]]),
            Severity::Critical,
        ];
        yield 'no metrics at all is unknown' => [[], Severity::Unknown];
        yield 'an empty block is skipped' => [['cvssMetricV40' => [], ...$v2(['cvssData' => ['baseScore' => 9.1]])], Severity::Critical];
        yield 'a block that is no list is skipped' => [
            ['cvssMetricV40' => 'not a list', ...$v2(['cvssData' => ['baseScore' => 9.1]])],
            Severity::Critical,
        ];
        yield 'a metric with neither band nor score is skipped' => [
            ['cvssMetricV31' => [['type' => 'Primary', 'cvssData' => []]], ...$v2(['cvssData' => ['baseScore' => 7.2]])],
            Severity::High,
        ];
        yield 'nothing usable anywhere is unknown' => [['cvssMetricV31' => [['type' => 'Primary']]], Severity::Unknown];
    }

    #[Test]
    #[DataProvider('recordWithoutMetricsProvider')]
    public function aRecordWithoutReadableMetricsIsUnknown(mixed $metrics): void
    {
        self::assertSame(Severity::Unknown, (new NvdSeverityReader())->severityOf(['id' => 'CVE-2026-0001', 'metrics' => $metrics]));
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function recordWithoutMetricsProvider(): iterable
    {
        yield 'metrics is a string' => ['not an object'];
        yield 'metrics is null' => [null];
    }

    #[Test]
    public function aRecordWithoutAMetricsKeyIsUnknown(): void
    {
        self::assertSame(Severity::Unknown, (new NvdSeverityReader())->severityOf(['id' => 'CVE-2026-0001']));
    }

    /**
     * @param array<string, mixed> $metrics
     */
    private function severityOf(array $metrics): Severity
    {
        return (new NvdSeverityReader())->severityOf(['id' => 'CVE-2026-0001', 'metrics' => $metrics]);
    }

    /**
     * @return array<string, mixed>
     */
    private static function fixtureMetrics(): array
    {
        $decoded = json_decode((string)file_get_contents(__DIR__ . '/Fixtures/CVE-2025-1217.json'), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        self::assertIsArray($decoded['metrics'] ?? null);

        $metrics = [];

        foreach ($decoded['metrics'] as $key => $value) {
            self::assertIsString($key);
            $metrics[$key] = $value;
        }

        return $metrics;
    }
}
