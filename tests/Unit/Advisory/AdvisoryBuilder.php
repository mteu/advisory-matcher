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
use mteu\AdvisoryMatcher\Advisory\AdvisoryReference;
use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Package\Ecosystem;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Version\AffectedVersions;

final class AdvisoryBuilder
{
    /**
     * @param list<AdvisoryReference> $references
     * @param string $remoteId a GitHub advisory id, filed as a reference
     */
    public static function build(
        string $advisoryId = 'PKSA-1111-2222-3333',
        string $packageName = 'vendor/package',
        Ecosystem $ecosystem = Ecosystem::Composer,
        string $remoteId = '',
        string $title = 'A vulnerability',
        string $link = 'https://example.invalid/advisory',
        string $cve = '',
        string $affectedVersions = '>=1.0.0,<1.6.0',
        Severity $severity = Severity::Medium,
        array $references = [],
        string $firstPatchedVersion = '',
    ): Advisory {
        return new Advisory(
            advisoryId: $advisoryId,
            package: self::packageUrlOf($ecosystem, $packageName),
            title: $title,
            link: $link,
            cve: $cve,
            affectedVersions: AffectedVersions::fromComposerConstraint($affectedVersions),
            reportedAt: new \DateTimeImmutable('2026-01-01T00:00:00+00:00'),
            severity: $severity,
            references: $remoteId === '' ? $references : [...$references, new AdvisoryReference('GitHub', $remoteId)],
            firstPatchedVersion: $firstPatchedVersion,
        );
    }

    /**
     * @param string $packageName ignored for the PHP runtime, which has one name only
     */
    public static function packageUrlOf(Ecosystem $ecosystem, string $packageName): PackageUrl
    {
        return match ($ecosystem) {
            Ecosystem::Composer => PackageUrl::fromPackageName('composer', $packageName),
            Ecosystem::Npm => PackageUrl::fromPackageName('npm', $packageName),
            Ecosystem::Php => PackageUrl::fromString('pkg:generic/php'),
            Ecosystem::Platform => PackageUrl::fromString('pkg:generic/httpd'),
            Ecosystem::Unknown => PackageUrl::fromPackageName('pypi', $packageName),
        };
    }

    /**
     * One advisory carrying every kind of identity, filed under this package.
     */
    public static function onPackage(PackageUrl $package): Advisory
    {
        return new Advisory(
            advisoryId: 'PKSA-1111-2222-3333',
            package: $package,
            title: 'A vulnerability',
            link: '',
            cve: 'CVE-2026-1234',
            affectedVersions: AffectedVersions::fromComposerConstraint('<1.0.0'),
            reportedAt: new \DateTimeImmutable('2026-01-01T00:00:00+00:00'),
            severity: Severity::High,
            references: [new AdvisoryReference('GitHub', 'GHSA-aaaa-bbbb-cccc')],
        );
    }
}
