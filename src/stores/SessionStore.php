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

final class SessionStore implements SpamStoreInterface
{
    public function __construct(private readonly string $keyPrefix = 'spamshield')
    {
    }

    /**
     * Get (by reference) the bucket for a namespace.
     *
     * @return array<int, array{0:int,1:string}> reference to an array of [timestamp, value]
     */
    private function &bucket(string $ns): array
    {
        if (\session_status() !== PHP_SESSION_ACTIVE) {
            \session_start();
        }

        if (! isset($_SESSION[$this->keyPrefix])) {
            $_SESSION[$this->keyPrefix] = [];
        }

        if (! isset($_SESSION[$this->keyPrefix][$ns])) {
            $_SESSION[$this->keyPrefix][$ns] = [];
        }

        return $_SESSION[$this->keyPrefix][$ns];
    }

    /**
     * @param string $ns
     * @param string $value
     * @param int $windowSeconds
     */
    public function remember(string $ns, string $value, int $windowSeconds): void
    {
        $now = \time();

        $bucket = & $this->bucket($ns);

        // prune
        foreach ($bucket as $i => [$ts, $val]) {
            if ($now - $ts > $windowSeconds) {
                unset($bucket[$i]);
            }
        }

        $bucket[] = [$now, $value];
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

        $bucket = & $this->bucket($ns);

        foreach ($bucket as [$ts, $val]) {
            if ($val === $value && $now - $ts <= $windowSeconds) {
                return true;
            }
        }

        return false;
    }
}
