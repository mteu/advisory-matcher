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

namespace mteu\AdvisoryMatcher\Version;

use Composer\Semver\Constraint\Constraint;
use Composer\Semver\Constraint\ConstraintInterface;
use Composer\Semver\VersionParser;

/**
 * @internal
 */
final class VersionConstraintMatcher
{
    /**
     * @var array<string, ConstraintInterface>
     */
    private array $parsedConstraints = [];

    /**
     * @var array<string, string>
     */
    private array $normalizedVersions = [];

    private ?VersionParser $versionParser = null;

    /**
     * @throws \UnexpectedValueException if either side is not valid Composer version syntax
     */
    public function satisfies(string $version, string $constraint): bool
    {
        $parser = $this->versionParser ??= new VersionParser();

        $parsedConstraint = $this->parsedConstraints[$constraint] ??= $parser->parseConstraints($constraint);
        $normalizedVersion = $this->normalizedVersions[$version] ??= $parser->normalize($version);

        return $parsedConstraint->matches(new Constraint('==', $normalizedVersion));
    }
}
