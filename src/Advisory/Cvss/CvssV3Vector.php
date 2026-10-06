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

namespace mteu\AdvisoryMatcher\Advisory\Cvss;

/**
 * @internal
 */
final readonly class CvssV3Vector
{
    private const array WEIGHTS = [
        'AV' => ['N' => 0.85, 'A' => 0.62, 'L' => 0.55, 'P' => 0.2],
        'AC' => ['L' => 0.77, 'H' => 0.44],
        'PR' => ['N' => 0.85, 'L' => 0.62, 'H' => 0.27],
        'PR_SCOPE_CHANGED' => ['N' => 0.85, 'L' => 0.68, 'H' => 0.5],
        'UI' => ['N' => 0.85, 'R' => 0.62],
        'CIA' => ['H' => 0.56, 'L' => 0.22, 'N' => 0.0],
    ];

    public function __construct(
        public string $attackVector,
        public string $attackComplexity,
        public string $privilegesRequired,
        public string $userInteraction,
        public string $scope,
        public string $confidentiality,
        public string $integrity,
        public string $availability,
    ) {
        $valid = array_key_exists($attackVector, self::WEIGHTS['AV'])
            && array_key_exists($attackComplexity, self::WEIGHTS['AC'])
            && array_key_exists($privilegesRequired, self::WEIGHTS['PR'])
            && array_key_exists($userInteraction, self::WEIGHTS['UI'])
            && in_array($scope, ['U', 'C'], true)
            && array_key_exists($confidentiality, self::WEIGHTS['CIA'])
            && array_key_exists($integrity, self::WEIGHTS['CIA'])
            && array_key_exists($availability, self::WEIGHTS['CIA']);

        if (!$valid) {
            throw new \InvalidArgumentException('A CVSS v3 base metric has a value its specification does not define.');
        }
    }

    /**
     * @throws \InvalidArgumentException when the string is not a CVSS v3 vector
     */
    public static function fromString(string $vector): self
    {
        $parts = explode('/', trim($vector));
        $version = array_shift($parts);

        if ($version !== 'CVSS:3.0' && $version !== 'CVSS:3.1') {
            throw new \InvalidArgumentException('Not a CVSS v3.0 or v3.1 vector.');
        }

        $metrics = [];

        foreach ($parts as $part) {
            $pair = explode(':', $part);

            if (count($pair) !== 2 || $pair[0] === '' || $pair[1] === '') {
                throw new \InvalidArgumentException('A CVSS v3 vector part is not a metric.');
            }

            if (array_key_exists($pair[0], $metrics)) {
                throw new \InvalidArgumentException('A CVSS v3 vector states a metric twice.');
            }

            $metrics[$pair[0]] = $pair[1];
        }

        // A missing base metric reads as '', which the constructor refuses.
        return new self(
            attackVector: $metrics['AV'] ?? '',
            attackComplexity: $metrics['AC'] ?? '',
            privilegesRequired: $metrics['PR'] ?? '',
            userInteraction: $metrics['UI'] ?? '',
            scope: $metrics['S'] ?? '',
            confidentiality: $metrics['C'] ?? '',
            integrity: $metrics['I'] ?? '',
            availability: $metrics['A'] ?? '',
        );
    }

    public function baseScore(): float
    {
        $scopeChanged = $this->scope === 'C';
        $impactSubScore = 1 - (1 - $this->weight('CIA', $this->confidentiality))
            * (1 - $this->weight('CIA', $this->integrity))
            * (1 - $this->weight('CIA', $this->availability));

        $impact = $scopeChanged
            ? 7.52 * ($impactSubScore - 0.029) - 3.25 * (($impactSubScore - 0.02) ** 15)
            : 6.42 * $impactSubScore;

        if ($impact <= 0) {
            return 0.0;
        }

        $exploitability = 8.22
            * $this->weight('AV', $this->attackVector)
            * $this->weight('AC', $this->attackComplexity)
            * $this->weight($scopeChanged ? 'PR_SCOPE_CHANGED' : 'PR', $this->privilegesRequired)
            * $this->weight('UI', $this->userInteraction);

        $score = $scopeChanged ? 1.08 * ($impact + $exploitability) : $impact + $exploitability;

        return $this->roundUp(min($score, 10.0));
    }

    private function weight(string $metric, string $value): float
    {
        return self::WEIGHTS[$metric][$value]
            ?? throw new \LogicException(sprintf('No CVSS v3 weight for %s:%s.', $metric, $value));
    }

    private function roundUp(float $value): float
    {
        $scaled = (int)round($value * 100_000);

        if ($scaled % 10_000 === 0) {
            return $scaled / 100_000.0;
        }

        return (floor($scaled / 10_000) + 1) / 10.0;
    }
}
