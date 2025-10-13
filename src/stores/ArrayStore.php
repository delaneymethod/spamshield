<?php

/**
 * SpamShield
 * (c) 2025 Sean Delaney
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the delaneymethod/spamshield package.
 * See the LICENSE file in the project root for license details.
 */

declare(strict_types=1);

namespace delaneymethod\spamshield\stores;

final class ArrayStore implements SpamStoreInterface
{
    /** @var array<string, array{int,string}[]> */
    private array $buckets = [];

    /**
     * @param string $ns
     * @param string $value
     * @param int $windowSeconds
     */
    public function remember(string $ns, string $value, int $windowSeconds): void
    {
        $now = \time();

        $bucket = $this->buckets[$ns] ?? [];

        // prune
        $bucket = \array_values(\array_filter($bucket, fn ($row) => $now - $row[0] <= $windowSeconds));

        // append
        $bucket[] = [$now, $value];

        $this->buckets[$ns] = $bucket;
    }

    /**
     * @param string $ns
     * @param string $value
     * @param int $windowSeconds
     * @return bool
     */
    public function seenRecently(string $ns, string $value, int $windowSeconds): bool
    {
        $now = \time();

        foreach ($this->buckets[$ns] ?? [] as [$ts, $val]) {
            if ($val === $value && $now - $ts <= $windowSeconds) {
                return true;
            }
        }

        return false;
    }
}
