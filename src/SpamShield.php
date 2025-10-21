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

class SpamShield
{
    private const THRESHOLD = 7; // final spam cutoff

    private const MINIMUM_MESSAGE_CHARACTERS = 25;

    private const MINIMUM_MESSAGE_WORDS = 4;

    private const MAXIMUM_FIELD_LENGTH = 200;

    private const GIBBERISH_WORD_LENGTH = 6;

    /** @var array<int, string> */
    private array $allowedValues = [];

    /** @var array<int, string> */
    private array $disposableDomains = ['mailinator.com', 'tempmail.com', '10minutemail.com', 'guerrillamail.com', 'trashmail.com', 'yopmail.com', 'sharklasers.com'];

    /** @var array<int, string> */
    private array $dnsBlockLists = ['zen.spamhaus.org', 'bl.spamcop.net'];

    /** @var array<int, string> */
    private array $suspectTopLevelDomains = ['top', 'xyz', 'click', 'icu', 'shop', 'link', 'today', 'win', 'live'];

    /** @var array<int, string> */
    private array $spamTerms = [
        'dofollow', 'backlinks', 'guest post', 'guestpost', 'sponsored post', 'link insertion',
        'seo package', 'casino', 'crypto', 'viagra', 'loan', 'telegram', 'whatsapp', 'adult',
        'brand mention', 'dripfeed', 'outreach', 'high da', 'high-da', 'guest blogging',
    ];

    /** @var array<int, string> */
    private array $phishingTerms = [
        'verify your account', 'confirm your account', 'reset your password', 'password reset',
        'login to your account', 'log in to your account', 'update your account', 'account verification',
        'account suspended', 'verify here', 'confirm here', 'billing update', 'payment details',
    ];

    /**
     * @param array<string, mixed> $payload
     * @param array<string, mixed> $meta
     * @return array{score:int, reasons:array<int,string>, is_spam:bool}
     */
    public function score(array $payload, array $meta = []): array
    {
        $fieldHandles = (array) ($meta['field_handles'] ?? []);
        $checkMxRecord = (bool) ($meta['check_mx_record'] ?? false);
        $checkDnsBlockLists = (bool) ($meta['check_dns_block_lists'] ?? false);
        $minimumWords = (int) ($meta['minimum_message_words'] ?? self::MINIMUM_MESSAGE_WORDS);
        $gibberishWordLength = (int) ($meta['gibberish_word_length'] ?? self::GIBBERISH_WORD_LENGTH);
        $minimumCharacters = (int) ($meta['minimum_message_characters'] ?? self::MINIMUM_MESSAGE_CHARACTERS);

        $payload = $this->buildPayloadFromFieldValues($payload);

        $totalPayload = count($payload);

        $score = 0;
        $reasons = [];

        // Gibberish
        $gibberishHits = 0;

        // If caller explicitly asked for more fields, scan only those (if present)
        $extraFieldHandles = array_values(array_filter($fieldHandles, fn($fieldHandle) => is_string($fieldHandle) && $fieldHandle !== 'message'));
        foreach ($extraFieldHandles as $extraFieldHandle) {
            if (!array_key_exists($extraFieldHandle, $payload)) {
                continue;
            }

            $value = trim($payload[$extraFieldHandle]);
            if ($value !== '' && $this->isGibberish($value, $gibberishWordLength)) {
                $gibberishHits++;
            }
        }

        // Email sanity
        $email = \trim($payload['email_address'] ?? '');
        if ($email !== '') {
            $email = \strtolower($email);

            if (! \filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $score += 2;

                $reasons[] = 'bad_email_format';
            }

            if ($checkMxRecord && ! $this->emailHasMXRecord($email)) {
                $score += 2;

                $reasons[] = 'no_mx_record';
            }

            if ($this->isDisposable($email)) {
                $score += 7;

                $reasons[] = 'disposable_email';
            }

            if ($this->suspectTopLevelDomains($email)) {
                $score += 2;

                $reasons[] = 'suspect_tld';
            }
        }

        // Message sanity
        $message = \trim($payload['message'] ?? '');
        if ($message !== '') {
            $messageLength = \mb_strlen($message);
            $wordCount = \preg_match_all('/\p{L}+/u', $message, $tmp);

            if ($messageLength < $minimumCharacters) {
                $score += 2;

                $reasons[] = 'short_message';
            }

            if ($wordCount < $minimumWords) {
                $score += 1;

                $reasons[] = 'low_word_count';
            }

            if (! $this->looksLikeASentence($message)) {
                $score += 1;

                $reasons[] = 'no_sentence_like_content';
            }

            $urlCount = $this->urlCount($message);
            $containsSpamTerms = $this->containsSpamTerms($message);
            $containsPhishTerms = $this->containsAnyPhrase($message, $this->phishingTerms);

            // URLs: keep single-link light, multi-link heavier
            if ($urlCount >= 1) {
                $score += 1;

                $reasons[] = 'contains_url';
            }

            if ($urlCount >= 2) {
                $score += 1;

                $reasons[] = 'multiple_urls';
            }

            // Language signals
            if ($containsSpamTerms) {
                $score += 2;

                $reasons[] = 'spammy_language';

                // Only nudge combo for spam terms
                if ($urlCount >= 1) {
                    $score += 1;

                    $reasons[] = 'spammy_link_combo';
                }
            }

            if ($containsPhishTerms) {
                $score += 5;

                $reasons[] = 'phishing_language';

                // Only nudge combo for phishing terms
                if ($urlCount >= 1) {
                    $score += 1;

                    $reasons[] = 'phishing_link_combo';
                }
            }

            $gibberishHits += $this->gibberishHitsFromValue($message, $gibberishWordLength);
        }

        // Telephone number sanity
        $phone = \trim($payload['telephone_number'] ?? '');
        if ($phone !== '') {
            $digits = \preg_replace('/\D+/', '', $phone);
            $isUS = (bool) \preg_match('/^(1)?\d{10}$/', $digits);
            $isUK = (bool) \preg_match('/^(44)?7\d{9}$|^07\d{9}$/', $digits);

            if (! ($isUS || $isUK)) {
                $score += 2;

                $reasons[] = 'invalid_telephone_number';
            }

            if ($this->obviouslyFakePhone($phone)) {
                $score += 2;

                $reasons[] = 'fake_phone_pattern';
            }
        }

        // Postal code sanity (UK-ish heuristic)
        $postcode = \trim($payload['postal_code'] ?? '');
        if ($postcode !== '') {
            if (\mb_strlen($postcode) > self::MAXIMUM_FIELD_LENGTH) {
                $score += 1;

                $reasons[] = 'field_too_long';
            }

            $trimmed = \strtoupper(\preg_replace('/\s+/', '', $postcode));
            $ukOk = \preg_match('/^[A-Z]{1,2}\d[A-Z\d]?\d[A-Z]{2}$/', $trimmed);

            if (! $ukOk && $this->isGibberish($postcode, $gibberishWordLength)) {
                $score += 2;

                $reasons[] = 'bad_postal_code';
            }
        }

        if ($gibberishHits >= 1) {
            if ($totalPayload === 1) {
                $score += 7;

                $reasons[] = 'one_field_count';
            } else {
                $score += 4;
            }

            $reasons[] = 'gibberish_fields';
        }

        if ($gibberishHits >= 2) {
            $score += 7;

            $reasons[] = 'multiple_gibberish_fields';
        }

        // DNS Block List
        $ip = \trim($meta['ip'] ?? '');
        if ($ip !== '' && $checkDnsBlockLists && $this->listedOnDnsBlockList($ip)) {
            $score += 2;

            $reasons[] = 'dns_blocklist_listed';
        }

        return [
            'ip' => $ip,
            'score' => $score,
            'reasons' => $reasons,
            'is_spam' => $score >= self::THRESHOLD,
        ];
    }

    /**
     * @param array<int, string> $allowedValues
     */
    public function setAllowedValues(array $allowedValues): void
    {
        $this->allowedValues = $allowedValues;
    }

    /**
     * @return array<int, string>
     */
    public function getAllowedValues(): array
    {
        return $this->allowedValues;
    }

    /**
     * @param array<int, string> $dnsBlockLists
     */
    public function setDnsBlockLists(array $dnsBlockLists): void
    {
        $this->dnsBlockLists = array_unique(array_merge($this->dnsBlockLists, $dnsBlockLists));
    }

    /**
     * @return array<int, string>
     */
    public function getDnsBlockLists(): array
    {
        return $this->dnsBlockLists;
    }

    public function urlCount(string $value): int
    {
        /** @var array{0: array<int, string>} $matches */
        $matches = [];
        \preg_match_all('~https?://\S+|www\.\S+~i', $value, $matches);

        return \count($matches[0]); // offset 0 always set by preg_match_all
    }

    /**
     * @param array<int, string> $phrases
     */
    public function containsAnyPhrase(string $value, array $phrases): bool
    {
        $value = \mb_strtolower($value);

        foreach ($phrases as $phrase) {
            $phrase = \mb_strtolower($phrase);

            // Match the full phrase with non-letter boundaries on both sides
            $pattern = '~(?<!\p{L})' . \preg_quote($phrase, '~') . '(?!\p{L})~u';
            if (\preg_match($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    public function containsSpamTerms(string $value): bool
    {
        $value = \mb_strtolower($value);

        foreach ($this->spamTerms as $spamTerm) {
            if (\str_contains($value, $spamTerm)) {
                return true;
            }
        }

        return false;
    }

    public function suspectTopLevelDomains(string $email): bool
    {
        $at = \strrpos($email, '@');
        if ($at === false) {
            return false;
        }

        $domain = \strtolower(\substr($email, $at + 1));
        if ($domain === '') {
            return false;
        }

        $parts = \explode('.', $domain); // array<int,string>
        $tld = \end($parts);
        if ($tld == false) {
            return false;
        }

        return \in_array($tld, $this->suspectTopLevelDomains, true);
    }

    public function obviouslyFakePhone(string $raw): bool
    {
        $digits = \preg_replace('/\D+/', '', $raw);
        if ($digits === '') {
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

    public function normalize(string $value): string
    {
        $value = \mb_strtolower($value);
        $value = \preg_replace('/\s+/u', ' ', $value);
        $value = \preg_replace('/[^a-z0-9\s]/u', '', $value);

        return \trim($value);
    }

    public function isTechnicalValue(string $value): bool
    {
        if (\preg_match('/[0-9\-]/', $value) && \preg_match('/^[A-Z0-9\-]{4,}$/', $value)) {
            return true;
        }

        if (\preg_match('/^[A-Z]{5,20}$/', $value)) {
            return true;
        }

        if (\in_array(\strtoupper($value), $this->getAllowedValues(), true)) {
            return true;
        }

        return false;
    }

    public function isGibberish(string $value, int $gibberishWordLength): bool
    {
        $value = \trim($value);
        if ($value === '') {
            return false;
        }

        $bad = 0;

        /** @var array<int,string> $words */
        $words = \preg_split('/\s+/', $value);

        foreach ($words as $word) {
            // Skip URLs
            if (\preg_match('~^(https?://|www\.)~i', $word)) {
                continue;
            }

            // Skip emails
            if (\filter_var($word, FILTER_VALIDATE_EMAIL)) {
                continue;
            }

            // Only analyze Latin-script words; skip if any non-Latin chars present
            if (!\preg_match('/^\p{Latin}+$/u', \preg_replace('/[^[:alpha:]]/u', '', $word))) {
                continue;
            }

            if (\mb_strlen($word) < $gibberishWordLength) {
                continue;
            }

            if ($this->isTechnicalValue($word)) {
                continue;
            }

            $letters = \preg_replace('/[^A-Za-z]/u', '', $word);
            if ($letters === '') {
                continue;
            }

            // vowel ratio
            $vowels = \preg_match_all('/[aeiouAEIOU]/u', $word);
            $ratio = $vowels ? ($vowels / \max(1, \mb_strlen($word))) : 0;
            if ($ratio < 0.2 || $ratio > 0.8) {
                $bad++;
            }

            // long consonant run
            if (\preg_match('/[^aeiouAEIOU]{5,}/u', $word)) {
                $bad++;
            }

            // mixed case weirdness
            if (\preg_match('/[A-Z].*[a-z].*[A-Z]/u', $word)) {
                $bad++;
            }

            if ($this->shannonEntropy($word) > 3.8) {
                $bad++;
            }
        }

        return $bad >= 2;
    }

    public function gibberishHitsFromValue(string $value, int $gibberishWordLength, int $takeLongest = 5): int
    {
        /** @var array{0: array<int, string>} $matches */
        $matches = [];
        \preg_match_all('/\p{L}{4,}/u', $value, $matches);
        $words = $matches[0];

        \usort($words, static fn (string $a, string $b): int => \mb_strlen($b) <=> \mb_strlen($a));
        $words = \array_slice($words, 0, $takeLongest);

        $hits = 0;

        foreach ($words as $w) {
            if ($this->isTechnicalValue($w)) {
                continue;
            }

            if ($this->isGibberish($w, $gibberishWordLength)) {
                $hits++;
            }
        }

        return $hits;
    }

    public function looksLikeASentence(string $value): bool
    {
        if (! \preg_match('/\s/u', $value)) {
            return false;
        }

        if (! \preg_match('/[aeiouAEIOU]/u', $value)) {
            return false;
        }

        if (\preg_match('/[.!?]$/u', \trim($value))) {
            return true;
        }

        return \str_word_count($value) >= 5;
    }

    public function shannonEntropy(string $value): float
    {
        $length = \mb_strlen($value);

        if ($length === 0) {
            return 0.0;
        }

        $freq = [];

        for ($i = 0; $i < $length; $i++) {
            $ch = \mb_substr($value, $i, 1);

            $freq[$ch] = ($freq[$ch] ?? 0) + 1;
        }

        $H = 0.0;

        foreach ($freq as $c) {
            $p = $c / $length;
            $H -= $p * \log($p, 2);
        }

        return $H;
    }

    public function emailHasMXRecord(string $email): bool
    {
        $at = \strrpos($email, '@');

        if ($at === false) {
            return false;
        }

        $domain = \substr($email, $at + 1);

        if ($domain === '') {
            return false;
        }

        return \checkdnsrr($domain, 'MX') || \checkdnsrr($domain, 'A');
    }

    public function isDisposable(string $email): bool
    {
        $at = \strrpos($email, '@');

        if ($at === false) {
            return false;
        }

        $domain = \strtolower(\substr($email, $at + 1));

        if ($domain === '') {
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

    public function listedOnDnsBlockList(string $ip): bool
    {
        // Skip IPv6 entirely (or implement a v6 DNSBL)
        if (\filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
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
            if (\preg_match($nonRoutablePattern, $ip)) {
                return false;
            }
        }

        // Only public IPv4: skip loopback/private/link-local/**reserved** per PHP's flags
        if (\filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false;
        }

        // At this point we have a public IPv4; do the lookup
        $reverse = \implode('.', \array_reverse(\explode('.', $ip)));

        foreach ($this->getDnsBlockLists() as $dnsBlockList) {
            if (@\checkdnsrr("$reverse.$dnsBlockList", 'A')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Build a normalized payload from the submitted form values ONLY.
     * - Canonicals are included iff an alias for them WAS POSTED (value may be empty).
     * - By default, ALL original submitted fields are also kept verbatim (incl. empty)
     *   so honeypots with arbitrary names always survive.
     *
     * @param array<string,mixed> $values
     * @param array<string,string> $overrides Optional canonicalKey => exact original key to force
     * @return array<string,string>
     */
    public function buildPayloadFromFieldValues(array $values, array $overrides = []): array
    {
        // 1) Normalize submitted values (trim + stringify arrays)
        $submitted = [];

        foreach ($values as $key => $value) {
            if (is_array($value)) {
                $value = implode(', ', array_map('strval', array_filter($value, fn($x) => $x !== null && $x !== '')));
            }

            $submitted[$key] = trim((string) $value);
        }

        // 2) Alias groups (matching only)
        $aliasGroups = [
            'full_name' => ['fullname', 'full_name', 'full-name', 'contactname', 'contact_name', 'contact-name', 'name'],
            'first_name' => ['firstname', 'first_name', 'first-name', 'fname', 'first'],
            'last_name' => ['lastname', 'last_name', 'last-name', 'lname', 'last', 'surname'],
            'email_address' => ['email', 'email_address', 'email-address', 'emailaddress', 'mail'],
            'telephone_number' => ['phone', 'phone_number', 'phone-number', 'phonenumber', 'telephone', 'tel', 'mobile', 'cell', 'cellphone'],
            'street_address_1' => ['street_address_1', 'streetaddress1', 'street-address-1', 'street-address1', 'street-address', 'streetaddress', 'street_address', 'address1', 'address'],
            'street_address_2' => ['street_address_2', 'streetaddress2', 'street-address-2', 'street-address2', 'address2', 'address_line_2', 'addressline2'],
            'town_city' => ['town_city', 'towncity', 'town', 'city'],
            'state_region' => ['state_region', 'stateregion', 'state', 'region', 'county', 'province'],
            'postal_code' => ['postal_code', 'postcode', 'post_code', 'zip', 'zip_code', 'zipcode', 'zippostalcode', 'zip_postal_code', 'zip-postal-code', 'company_zip_code', 'companyzipcode'],
            'country' => ['country'],
            'message' => ['how_can_we_help', 'how_can_we_help_you', 'commentsquestions', 'comments_questions', 'comments-questions', 'contact_question', 'description', 'comments', 'message', 'enquiry', 'inquiry', 'details', 'notes', 'special_instructions', 'additionaldetails', 'question', 'questions', 'scope', 'brief', 'content', 'how_did_you_hear_about_us', 'how-did-you-hear-about-us', 'howdidyouhearaboutus'],
            'company_name' => ['company_name', 'company-name', 'company', 'organisation', 'organization', 'org', 'business', 'employer'],
        ];

        $normalized = static fn(string $key): string => preg_replace('/[^a-z0-9]+/i', '', mb_strtolower($key)) ?? $key;

        // Build normalized-key => original-key map for submitted fields
        $normalizedMap = [];

        foreach ($submitted as $key => $_) {
            $normalizedKey = $normalized($key);

            if (!isset($normalizedMap[$normalizedKey])) {
                $normalizedMap[$normalizedKey] = $key;
            }
        }

        // Helper: did the request POST any alias for this canonical?
        $hasAlias = function (array $aliases) use ($normalizedMap, $normalized): bool {
            foreach ($aliases as $alias) {
                if (isset($normalizedMap[$normalized($alias)])) {
                    return true;
                }
            }

            return false;
        };

        // Helper: fetch first non-empty value among aliases (or a specific override key)
        $consumed = [];

        $getByAliases = function (array $aliases, ?string $overrideKey = null) use ($submitted, $normalizedMap, $normalized, &$consumed): string {
            if ($overrideKey && array_key_exists($overrideKey, $submitted)) {
                $consumed[$overrideKey] = true;

                return (string) $submitted[$overrideKey]; // may be empty
            }

            foreach ($aliases as $alias) {
                $n = $normalized($alias);

                if (isset($normalizedMap[$n])) {
                    $orig = $normalizedMap[$n];
                    $consumed[$orig] = true;

                    return (string) ($submitted[$orig] ?? ''); // may be empty
                }
            }

            return '';
        };

        // Index of ALL alias names (to suppress passthrough)
        $aliasIndex = [];

        foreach ($aliasGroups as $aliases) {
            foreach ($aliases as $a) {
                $aliasIndex[$normalized($a)] = true;
            }
        }

        $result = [];

        // 3) full_name: include if a direct alias was POSTed OR if any first/last alias was POSTed
        $fullNameIncluded = $hasAlias($aliasGroups['full_name']) || $hasAlias($aliasGroups['first_name']) || $hasAlias($aliasGroups['last_name']);
        if ($fullNameIncluded) {
            // prefer direct alias; else compose from first+last (values may be empty if they were posted empty)
            $result['full_name'] = $getByAliases($aliasGroups['full_name']) ?: trim($getByAliases($aliasGroups['first_name']) . ' ' . $getByAliases($aliasGroups['last_name']));
        }

        // 4) Other canonicals: include if an alias was POSTed (values may be empty if they were posted empty)
        $canonicalKeys = ['email_address', 'telephone_number', 'street_address_1', 'street_address_2', 'town_city', 'state_region', 'postal_code', 'country', 'message', 'company_name'];
        foreach ($canonicalKeys as $canonicalKey) {
            if ($hasAlias($aliasGroups[$canonicalKey])) {
                $result[$canonicalKey] = $getByAliases($aliasGroups[$canonicalKey], $overrides[$canonicalKey] ?? null);
            }
        }

        // 5) Passthrough: keep ALL submitted fields (incl. empty) EXCEPT any that were consumed to build a canonical.
        foreach ($submitted as $key => $value) {
            // if this original field fed a canonical, don't add it again
            if (isset($consumed[$key])) {
                continue;
            }

            // don’t leak alias fields
            if (isset($aliasIndex[$normalized($key)])) {
                continue;
            }

            // don't overwrite anything already set under the same key
            if (array_key_exists($key, $result)) {
                continue;
            }

            $result[$key] = $value;
        }

        return $result;
    }
}
