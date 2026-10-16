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

use Rector\Config\RectorConfig;

return RectorConfig::configure()
    ->withPaths([
        dirname(__DIR__, 2) . '/src',
    ])
    // The PSR interfaces and the package URL parser are not on this toolchain's autoloader,
    // so every type they return would read as mixed.
    ->withAutoloadPaths([
        dirname(__DIR__, 2) . '/.build/vendor/psr',
        dirname(__DIR__, 2) . '/.build/vendor/package-url/packageurl-php/src',
    ])
    ->withPhpSets(php83: true)
    ->withTypeCoverageLevel(0)
    ->withDeadCodeLevel(0)
    ->withCodeQualityLevel(0);
