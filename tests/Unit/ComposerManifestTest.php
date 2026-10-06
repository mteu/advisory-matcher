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

namespace mteu\AdvisoryMatcher\Tests\Unit;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class ComposerManifestTest extends TestCase
{
    private const string PUBLIC_REPOSITORY = 'https://github.com/mteu/advisory-matcher';

    #[Test]
    public function thePackageStandsInForNoOtherPackage(): void
    {
        self::assertArrayNotHasKey('replace', self::manifest());
    }

    #[Test]
    public function everyPackageDependencyHasABoundedConstraint(): void
    {
        $manifest = self::manifest();

        $unbounded = [];
        foreach (['require', 'require-dev'] as $section) {
            $dependencies = $manifest[$section] ?? [];
            self::assertIsArray($dependencies);

            foreach ($dependencies as $name => $constraint) {
                if (str_starts_with((string)$name, 'ext-')) {
                    continue;
                }
                if ($constraint === '*') {
                    $unbounded[] = $section . ': ' . $name;
                }
            }
        }

        self::assertSame([], $unbounded);
    }

    #[Test]
    public function packagistCanLinkTheIssuesTheSourceAndTheSecurityPolicy(): void
    {
        $support = self::manifest()['support'] ?? [];
        self::assertIsArray($support);

        foreach (['issues', 'source', 'security'] as $key) {
            self::assertArrayHasKey($key, $support);
            self::assertIsString($support[$key]);
            self::assertStringStartsWith('https://', $support[$key]);
        }
    }

    #[Test]
    public function everyLinkPointsToThePublicRepository(): void
    {
        $manifest = self::manifest();
        $support = $manifest['support'] ?? [];
        self::assertIsArray($support);

        $links = ['homepage' => $manifest['homepage'] ?? ''];
        foreach ($support as $key => $link) {
            $links['support.' . $key] = $link;
        }

        foreach ($links as $key => $link) {
            self::assertIsString($link);
            self::assertStringStartsWith(self::PUBLIC_REPOSITORY, $link, $key);
            self::assertStringNotContainsString('advisory-matcher-src', $link, $key);
        }
    }

    #[Test]
    public function packagistCanFindThePackageByKeyword(): void
    {
        $keywords = self::manifest()['keywords'] ?? [];
        self::assertIsArray($keywords);

        self::assertContains('security', $keywords);
        self::assertContains('advisory', $keywords);
        self::assertContains('vulnerability', $keywords);
    }

    /**
     * @return array<array-key, mixed> decoded JSON, whose shape is what is under test
     */
    private static function manifest(): array
    {
        $manifest = json_decode(
            (string)file_get_contents(dirname(__DIR__, 2) . '/composer.json'),
            true,
            flags: JSON_THROW_ON_ERROR,
        );
        self::assertIsArray($manifest);

        return $manifest;
    }
}
