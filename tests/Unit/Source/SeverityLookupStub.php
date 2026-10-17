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

namespace mteu\AdvisoryMatcher\Tests\Unit\Source;

use mteu\AdvisoryMatcher\Advisory\Severity;
use mteu\AdvisoryMatcher\Source\SeverityLookup;
use mteu\AdvisoryMatcher\Source\SourceFailure;

final class SeverityLookupStub implements SeverityLookup
{
    /**
     * @var list<string>
     */
    private array $lookedUp = [];

    /**
     * @var list<list<string>>
     */
    private array $storedAskedFor = [];

    /**
     * @param array<string, Severity|SourceFailure> $answers keyed by CVE id, any other id is Unknown
     * @param array<string, Severity> $stored keyed by CVE id
     */
    public function __construct(
        private readonly array $answers = [],
        private readonly array $stored = [],
    ) {
    }

    public function severityForCve(string $cveId): Severity|SourceFailure
    {
        $this->lookedUp[] = $cveId;

        return $this->answers[$cveId] ?? Severity::Unknown;
    }

    public function storedSeveritiesForCves(array $cveIds): array
    {
        if (!array_is_list($cveIds)) {
            throw new \LogicException('The interface takes a list of ids.');
        }

        $this->storedAskedFor[] = $cveIds;

        return array_intersect_key($this->stored, array_flip($cveIds));
    }

    /**
     * @return list<string>
     */
    public function lookedUp(): array
    {
        return $this->lookedUp;
    }

    /**
     * @return list<list<string>>
     */
    public function storedAskedFor(): array
    {
        return $this->storedAskedFor;
    }
}
