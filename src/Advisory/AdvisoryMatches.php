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

namespace mteu\AdvisoryMatcher\Advisory;

final readonly class AdvisoryMatches
{
    /**
     * @param list<Advisory> $affected
     * @param list<Advisory> $notAffected
     * @param list<Advisory> $undetermined
     */
    public function __construct(
        public array $affected = [],
        public array $notAffected = [],
        public array $undetermined = [],
    ) {
    }

    public function hasAffected(): bool
    {
        return $this->affected !== [];
    }

    public function hasUndetermined(): bool
    {
        return $this->undetermined !== [];
    }
}
