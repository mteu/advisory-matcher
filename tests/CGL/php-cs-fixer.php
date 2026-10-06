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

$config = new \PhpCsFixer\Config();
$config->setParallelConfig(\PhpCsFixer\Runner\Parallel\ParallelConfigFactory::detect());
$config->getFinder()->in(dirname(__DIR__, 2));

return $config;
