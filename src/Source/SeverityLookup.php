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

namespace mteu\AdvisoryMatcher\Source;

use mteu\AdvisoryMatcher\Advisory\Severity;

interface SeverityLookup
{
    /**
     * Severity::Unknown when the record exists but carries no score, or when there is no record.
     * Outages are returned as a SourceFailure, but never thrown.
     */
    public function severityForCve(string $cveId): Severity|SourceFailure;

    /**
     * Answers only from what is already stored, so it never costs a remote call.
     * An id missing from the result needs severityForCve().
     *
     * @param list<string> $cveIds
     * @return array<string, Severity> keyed by the id as given
     */
    public function storedSeveritiesForCves(array $cveIds): array;
}
