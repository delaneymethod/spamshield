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

final class NullStore implements SpamStoreInterface
{
    /**
     * @param string $ns
     * @param string $value
     * @param int $windowSeconds
     */
    public function remember(string $ns, string $value, int $windowSeconds): void
    {
    }

    /**
     * @param string $ns
     * @param string $value
     * @param int $windowSeconds
     * @return bool
     */
    public function seenRecently(string $ns, string $value, int $windowSeconds): bool
    {
        return false;
    }
}
