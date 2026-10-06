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
final class PublicApiTest extends TestCase
{
    private const string ROOT_NAMESPACE = 'mteu\\AdvisoryMatcher\\';

    #[Test]
    public function everyTypeInSrcIsEitherListedAsPublicOrMarkedInternal(): void
    {
        $listedAsPublic = $this->typesListedAsPublic();

        $neither = [];
        $both = [];
        foreach ($this->typesInSrc() as $relativeName) {
            $isListed = in_array($relativeName, $listedAsPublic, true);
            $isInternal = $this->isMarkedInternal($relativeName);

            if (!$isListed && !$isInternal) {
                $neither[] = $relativeName;
            }
            if ($isListed && $isInternal) {
                $both[] = $relativeName;
            }
        }

        self::assertSame([], $neither, 'Neither listed in docs/api.md nor marked @internal.');
        self::assertSame([], $both, 'Listed as public in docs/api.md, yet marked @internal.');
    }

    #[Test]
    public function everyTypeListedAsPublicExistsInSrc(): void
    {
        $missing = array_values(array_diff($this->typesListedAsPublic(), $this->typesInSrc()));

        self::assertSame([], $missing, 'Listed as public in docs/api.md, but not a type in src/.');
    }

    #[Test]
    public function theApiDocListsPublicTypes(): void
    {
        self::assertNotSame([], $this->typesListedAsPublic());
    }

    /**
     * @return list<string> names relative to the root namespace, such as `Source\PackageRef`
     */
    private function typesInSrc(): array
    {
        $src = dirname(__DIR__, 2) . '/src';
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($src, \FilesystemIterator::SKIP_DOTS));

        $names = [];
        foreach ($files as $file) {
            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }
            $relativePath = substr($file->getPathname(), strlen($src) + 1, -strlen('.php'));
            $names[] = str_replace('/', '\\', $relativePath);
        }
        sort($names);

        return $names;
    }

    /**
     * @return list<string> names relative to the root namespace, as docs/api.md spells them
     */
    private function typesListedAsPublic(): array
    {
        $api = (string)file_get_contents(dirname(__DIR__, 2) . '/docs/api.md');

        preg_match_all('/^- \[`((?:[A-Z]\w*\\\\)+[A-Z]\w*)`\]\(/m', $api, $matches);

        return array_values(array_unique($matches[1]));
    }

    private function isMarkedInternal(string $relativeName): bool
    {
        $name = self::ROOT_NAMESPACE . $relativeName;
        if (class_exists($name) || interface_exists($name)) {
            $docComment = (new \ReflectionClass($name))->getDocComment();

            return $docComment !== false && preg_match('/^\s*\*\s*@internal\b/m', $docComment) === 1;
        }

        self::fail(sprintf('%s is in src/ but does not autoload.', $name));
    }
}
