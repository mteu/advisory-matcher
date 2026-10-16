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

namespace mteu\AdvisoryMatcher\Source\Http;

use Psr\Http\Message\RequestInterface;

/**
 * @internal
 */
final readonly class UserAgent
{
    public const string LIBRARY_DEFAULT = 'mteu/advisory-matcher (+https://github.com/mteu/advisory-matcher)';

    private string $value;

    /**
     * @throws \InvalidArgumentException when the value is not printable ASCII
     */
    public function __construct(string $value)
    {
        $value = trim($value);

        // A line break would end the header and let the consumer start another.
        // Refused when the source is built, not on the first request.
        if (preg_match('/^[\x20-\x7E]*$/', $value) !== 1) {
            throw new \InvalidArgumentException('A User-Agent must be printable ASCII, without line breaks or other control characters.');
        }

        $this->value = $value;
    }

    public function applyTo(RequestInterface $request): RequestInterface
    {
        if ($this->value === '') {
            return $request;
        }

        return $request->withHeader('User-Agent', $this->value);
    }
}
