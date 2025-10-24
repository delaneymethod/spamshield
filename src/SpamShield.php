<?php

/**
 * SpamShield
 * (c) 2025 Sean Delaney
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the delaneymethod/spamshield package.
 * See the LICENSE file in the project root for license details.
 */

namespace delaneymethod\spamshield;

use delaneymethod\spamshield\helpers\GibberishHelper;

class SpamShield
{
    /** @var array */
    public array $allowedTerms = [];

    /** @var array */
    public array $disposableDomains = ['mailinator.com', 'tempmail.com', '10minutemail.com', 'guerrillamail.com', 'trashmail.com', 'yopmail.com', 'sharklasers.com'];

    /** @var array */
    public array $dnsBlockLists = ['zen.spamhaus.org', 'bl.spamcop.net'];

    /** @var array */
    public array $suspectTopLevelDomains = ['top', 'xyz', 'click', 'icu', 'shop', 'link', 'today', 'win', 'live'];

    /** @var array */
    public array $spamTerms = [
        'dofollow', 'backlinks', 'guest post', 'guestpost', 'sponsored post', 'link insertion',
        'seo package', 'casino', 'crypto', 'viagra', 'loan', 'telegram', 'whatsapp', 'adult',
        'brand mention', 'dripfeed', 'outreach', 'high da', 'high-da', 'guest blogging',
    ];

    /** @var array */
    public array $phishingTerms = [
        'verify your account', 'confirm your account', 'reset your password', 'password reset',
        'login to your account', 'log in to your account', 'update your account', 'account verification',
        'account suspended', 'verify here', 'confirm here', 'billing update', 'payment details',
    ];

    private const THRESHOLD = 7;

    private const GIBBERISH_WORD_MINIMUM_LENGTH = 6;

    /**
     * @param  array $payload
     * @param  array $meta
     * @return array
     */
    public function score(array $payload, array $meta = []): array
    {
        $checkMxRecord = (bool) ($meta['check_mx_record'] ?? false);
        $checkDnsBlockLists = (bool) ($meta['check_dns_block_lists'] ?? false);
        $gibberishWordMinimumLength = (int) ($meta['gibberish_word_minimum_length'] ?? self::GIBBERISH_WORD_MINIMUM_LENGTH);

        $totalPayload = count($payload);

        $score = 0;
        $reasons = [];
        $gibberishHits = 0;

        // Payloads check
        foreach ($payload as $field => $value) {
            if (!empty($value)) {
                $urlCount = $this->urlCount($value);
                $containsSpamTerms = $this->containsSpamTerms($value);
                $containsPhishTerms = $this->containsPhishingTerms($value);

                // URLs: keep single-link light, multi-link heavier
                if ($urlCount >= 1) {
                    $score += 1;

                    $reasons[$field] = 'contains_url';
                }

                if ($urlCount >= 2) {
                    $score += 1;

                    $reasons[$field] = 'contains_multiple_urls';
                }

                // Language signals
                if ($containsSpamTerms) {
                    $score += 2;

                    $reasons[$field] = 'contains_spammy_language';

                    // Only nudge combo for spam terms
                    if ($urlCount >= 1) {
                        $score += 1;

                        $reasons[$field] = 'contains_spammy_link_combo';
                    }
                }

                if ($containsPhishTerms) {
                    $score += 5;

                    $reasons[$field] = 'contains_phishing_language';

                    // Only nudge combo for phishing terms
                    if ($urlCount >= 1) {
                        $score += 1;

                        $reasons[$field] = 'contains_phishing_link_combo';
                    }
                }

                $analysis = GibberishHelper::analyzeGibberish($value, $gibberishWordMinimumLength, $this->allowedTerms);
                if ($analysis['is_gibberish']) {
                    $gibberishHits++;
                }

                // Always keep the analysis for debugging/reporting:
                if (!empty($analysis['bad_word_count']) || !empty($analysis['short_word_junk_count']) || !empty($analysis['words'])) {
                    $reasons[$field] = $analysis;
                }

                if ($this->looksLikeEmail($value)) {
                    $email = \strtolower($value);

                    if ($checkMxRecord && !$this->emailHasMXRecord($email)) {
                        $score += 2;

                        $reasons[$field] = 'email_address_no_mx_record_found';
                    }

                    if ($this->isDisposable($email)) {
                        $score += 7;

                        $reasons[$field] = 'email_address_is_disposable';
                    }

                    if ($this->hasSuspectTopLevelDomain($email)) {
                        $score += 2;

                        $reasons[$field] = 'email_address_contains_suspect_tld';
                    }
                }

                if ($this->looksLikePhoneCandidate($value)) {
                    if (!$this->isValidPhoneNumber($value)) {
                        $score += 2;

                        $reasons[$field] = 'phone_number_is_invalid';
                    }

                    if ($this->isFakePhoneNumber($value)) {
                        $score += 2;

                        $reasons[$field] = 'phone_number_is_fake';
                    }
                }
            }
        }

        if ($gibberishHits >= 1) {
            if ($totalPayload === 1) {
                $score += 7;
            } else {
                $score += 4;
            }

            $reasons[] = 'one_gibberish_field_found';
        }

        if ($gibberishHits >= 2) {
            $score += 7;

            $reasons[] = 'multiple_gibberish_fields_found';
        }

        // IP address
        $ip = \trim($meta['ip'] ?? '');
        if (!empty($ip) && $checkDnsBlockLists && $this->listedOnDnsBlockList($ip)) {
            $score += 2;

            $reasons[] = 'ip_is_listed_on_dns_block_list';
        }

        return [
            'ip' => $ip,
            'score' => $score,
            'reasons' => $reasons,
            'is_spam' => $score >= self::THRESHOLD,
        ];
    }

    /**
     * @param array $allowedTerms
     * @return void
     */
    public function setAllowedTerms(array $allowedTerms): void
    {
        $norm = array_values(array_filter(array_map(
            static fn ($allowedTerm) => trim((string) $allowedTerm),
            $allowedTerms
        ), static fn ($allowedTerm) => $allowedTerm !== ''));

        $this->allowedTerms = array_unique(array_merge($this->allowedTerms, $norm));
    }

    /**
     * @param array $dnsBlockLists
     * @return void
     */
    public function setDnsBlockLists(array $dnsBlockLists): void
    {
        $this->dnsBlockLists = array_unique(array_merge($this->dnsBlockLists, $dnsBlockLists));
    }

    /**
     * @param string $value
     * @return int
     */
    public function urlCount(string $value): int
    {
        $matches = [];

        \preg_match_all('~https?://\S+|www\.\S+~i', $value, $matches);

        return \count($matches[0]); // offset 0 always set by preg_match_all
    }

    /**
     * @param string $value
     * @return bool
     */
    public function containsPhishingTerms(string $value): bool
    {
        $value = \mb_strtolower($value);

        foreach ($this->phishingTerms as $phishingTerm) {
            $phishingTerm = \mb_strtolower($phishingTerm);

            // Match the full phrase with non-letter boundaries on both sides
            $pattern = '~(?<!\p{L})' . \preg_quote($phishingTerm, '~') . '(?!\p{L})~u';
            if (\preg_match($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string $value
     * @return bool
     */
    public function containsSpamTerms(string $value): bool
    {
        $value = \mb_strtolower($value);

        foreach ($this->spamTerms as $spamTerm) {
            if (\str_contains($value, $spamTerm)) {
                $spamTermLowerCase = mb_strtolower($spamTerm);
                $pattern = '~(?<!\p{L})' . preg_quote($spamTermLowerCase, '~') . '(?!\p{L})~u';

                if (preg_match($pattern, $value)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param string $value
     * @return bool
     */
    public function hasSuspectTopLevelDomain(string $value): bool
    {
        $at = \strrpos($value, '@');
        if ($at === false) {
            return false;
        }

        $domain = \strtolower(\substr($value, $at + 1));
        if (empty($domain)) {
            return false;
        }

        $parts = \explode('.', $domain); // array<int,string>
        $tld = \end($parts);
        if (!$tld) {
            return false;
        }

        return \in_array($tld, $this->suspectTopLevelDomains, true);
    }

    /**
     * @param string $value
     * @return bool
     */
    public function looksLikePhoneCandidate(string $value): bool
    {
        $value = trim($value);
        if (empty($value)) {
            return false;
        }

        // ignore obvious extensions
        $value = preg_replace('/(?:\s*(?:ext\.?|x|#)\s*\d+)\s*$/i', '', $value) ?? $value;

        $digits = preg_replace('/\D+/', '', $value) ?? '';

        // “candidate” if there are 7+ digits (so we’ll validate it)
        return strlen($digits) >= 7;
    }

    /**
     * @param string $value
     * @return bool
     */
    public function isValidPhoneNumber(string $value): bool
    {
        $value = trim($value);
        if (empty($value)) {
            return false;
        }

        $value = preg_replace('/(?:\s*(?:ext\.?|x|#)\s*\d+)\s*$/i', '', $value) ?? $value;
        $digits = preg_replace('/\D+/', '', $value) ?? '';

        // ---- NANP (US/CA etc.) ----
        if (preg_match('/^(1)?(\d{10})$/', $digits, $m)) {
            $national = $m[2]; // safe: present if regex matched
            // NXXNXXXXXX — area & exchange can’t start with 0 or 1
            return (bool) preg_match('/^[2-9]\d{2}[2-9]\d{6}$/', $national);
        }

        // ---- UK (national or E.164) ----
        $uk = $digits;
        if (str_starts_with($uk, '44')) {
            $uk = substr($uk, 2);
            if (!str_starts_with($uk, '0')) {
                $uk = '0' . $uk; // restore national leading 0
            }
        }

        // 01/02/03/07/08/09 patterns mostly 11 digits (very rough, but useful)
        return (bool) preg_match('/^0\d{9,10}$/', $uk);
    }

    /**
     * @param string $value
     * @return bool
     */
    public function isFakePhoneNumber(string $value): bool
    {
        $digits = \preg_replace('/\D+/', '', $value);
        if (empty($digits)) {
            return false;
        }

        // same digit 7+
        if (\preg_match('/^(.)\1{6,}$/', $digits)) {
            return true;
        }

        // many zeros
        if (\preg_match('/^0{6,}$/', $digits)) {
            return true;
        }

        if (\strlen($digits) >= 10 && \substr_count($digits, '0') >= 6) {
            return true;
        }

        return false;
    }

    /**
     * @param string $value
     * @return bool
     */
    public function looksLikeEmail(string $value): bool
    {
        $value = trim($value);

        return $value !== '' && filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * @param string $value
     * @return bool
     */
    public function emailHasMXRecord(string $value): bool
    {
        $at = \strrpos($value, '@');

        if ($at === false) {
            return false;
        }

        $domain = \substr($value, $at + 1);

        if ($domain === '') {
            return false;
        }

        return \checkdnsrr($domain, 'MX') || \checkdnsrr($domain, 'A');
    }

    /**
     * @param string $value
     * @return bool
     */
    public function isDisposable(string $value): bool
    {
        $at = \strrpos($value, '@');
        if ($at === false) {
            return false;
        }

        $domain = \strtolower(\substr($value, $at + 1));
        if (empty($domain)) {
            return false;
        }

        if (\in_array($domain, $this->disposableDomains, true)) {
            return true;
        }

        foreach ($this->disposableDomains as $disposableDomain) {
            if (\str_ends_with($domain, '.' . $disposableDomain)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string $value
     * @return bool
     */
    public function listedOnDnsBlockList(string $value): bool
    {
        // Skip IPv6 entirely (or implement a v6 DNSBL)
        if (\filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return false;
        }

        // Explicitly skip well-known non-routable/documentation ranges
        // RFC 5737 (TEST-NET): 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        // Benchmarking: 198.18.0.0/15, Carrier-Grade NAT: 100.64.0.0/10, Loopback/Private/Link-local: handled below too
        $nonRoutablePatterns = [
            '/^192\.0\.2\./', // TEST-NET-1
            '/^198\.51\.100\./', // TEST-NET-2
            '/^203\.0\.113\./', // TEST-NET-3
            '/^198\.(18|19)\./', // 198.18.0.0/15 benchmarking
            '/^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./', // 100.64.0.0/10 CGNAT
        ];

        foreach ($nonRoutablePatterns as $nonRoutablePattern) {
            if (\preg_match($nonRoutablePattern, $value)) {
                return false;
            }
        }

        // Only public IPv4: skip loopback/private/link-local/**reserved** per PHP's flags
        if (\filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false;
        }

        // At this point we have a public IPv4; do the lookup
        $reverse = \implode('.', \array_reverse(\explode('.', $value)));

        foreach ($this->dnsBlockLists as $dnsBlockList) {
            if (@\checkdnsrr("$reverse.$dnsBlockList", 'A')) {
                return true;
            }
        }

        return false;
    }
}
