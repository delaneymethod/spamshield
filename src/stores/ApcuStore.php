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

final class ApcuStore implements SpamStoreInterface
{
    public function __construct(private readonly string $keyPrefix = 'spamshield')
    {
    }

    private function key(string $ns): string
    {
        return $this->keyPrefix . ':' . $ns;
    }

    /**
     * @param string $ns
     * @param string $value
     * @param int $windowSeconds
     */
    public function remember(string $ns, string $value, int $windowSeconds): void
    {
        if (! \function_exists('apcu_fetch') || ! \ini_get('apc.enabled')) {
            return;
        }

        $key = $this->key($ns);

        $now = \time();

        $bucket = \apcu_fetch($key) ?: [];
        $bucket = \array_values(\array_filter($bucket, fn ($row) => $now - $row[0] <= $windowSeconds));

        $bucket[] = [$now, $value];

        \apcu_store($key, $bucket, $windowSeconds);
    }

    /**
     * @param string $ns
     * @param string $value
     * @param int $windowSeconds
     * @return bool
     */
    public function seenRecently(string $ns, string $value, int $windowSeconds): bool
    {
        if (! \function_exists('apcu_fetch') || ! \ini_get('apc.enabled')) {
            return false;
        }

        $key = $this->key($ns);

        $now = \time();

        $bucket = \apcu_fetch($key) ?: [];

        foreach ($bucket as [$ts, $val]) {
            if ($val === $value && $now - $ts <= $windowSeconds) {
                return true;
            }
        }

        return false;
    }
}
