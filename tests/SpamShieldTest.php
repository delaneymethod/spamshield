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

namespace delaneymethod\spamshield\tests;

use delaneymethod\spamshield\SpamShield;
use delaneymethod\spamshield\stores\ArrayStore;
use PHPUnit\Framework\TestCase;

final class SpamShieldTest extends TestCase
{
    private SpamShield $spamShield;

    protected function setUp(): void
    {
        $this->spamShield = new SpamShield();
        $this->spamShield->setStore(new ArrayStore());
    }

    public function testFixtures(): void
    {
        $fixtures = require __DIR__ . '/_data/spamshield-fixtures.php';

        foreach ($fixtures as $fixture) {
            $meta = $fixture['meta'] ?? [];
            $meta['skip_dns_block_list'] = true;
            $meta['skip_mx_record_check'] = true;

            $result = $this->spamShield->score($fixture['payload'], $meta);
            $message = $fixture['label'] . ' => ' . \json_encode($result);

            if ($fixture['expect'] === 'ham') {
                $this->assertFalse($result['is_spam'], $message);
            } else {
                $this->assertTrue($result['is_spam'], $message);
            }
        }
    }

    public function testBuildPayloadFromFieldValues(): void
    {
        $payload = $this->spamShield->buildPayloadFromFieldValues([
            'first_name' => 'Ada',
            'lastName' => 'Lovelace',
            'email-address' => 'ada@example.com',
            'phoneNumber' => '+1 212 555 7788',
            'zip' => '10001',
            'comments' => 'Hello there, I would like a quote.',
            'company' => 'Analytical Engines Ltd',
        ]);

        $this->assertSame('Ada Lovelace', $payload['full_name']);
        $this->assertSame('ada@example.com', $payload['email_address']);
        $this->assertSame('+1 212 555 7788', $payload['telephone_number']);
        $this->assertSame('10001', $payload['postal_code']);
        $this->assertSame('Hello there, I would like a quote.', $payload['message']);
        $this->assertSame('Analytical Engines Ltd', $payload['company_name']);
    }

    public function testIsTechnicalValue(): void
    {
        // Model/SKU-ish uppercase with digits or hyphens
        $this->assertTrue($this->spamShield->isTechnicalValue('MDSDMDPV'));
        $this->assertTrue($this->spamShield->isTechnicalValue('ABC-1234'));

        // Normal human words should be false
        $this->assertFalse($this->spamShield->isTechnicalValue('Mitsubishi'));
        $this->assertFalse($this->spamShield->isTechnicalValue('hello'));
    }

    public function testSetAllowedValuesRoundTrip(): void
    {
        $this->assertSame([], $this->spamShield->getAllowedValues());

        $this->spamShield->setAllowedValues(['MITSUBISHI', 'FANUC']);

        $this->assertSame(['MITSUBISHI', 'FANUC'], $this->spamShield->getAllowedValues());
    }

    public function testAllowedValuesToggleIsTechnicalValue(): void
    {
        // With no allowlist, lowercase brand should NOT be treated as technical
        $this->spamShield->setAllowedValues([]);

        $this->assertFalse($this->spamShield->isTechnicalValue('mitsubishi'));

        // After allowing, it should be recognized (case-insensitive)
        $this->spamShield->setAllowedValues(['MITSUBISHI']);

        $this->assertTrue($this->spamShield->isTechnicalValue('mitsubishi'));
        $this->assertTrue($this->spamShield->isTechnicalValue('MITSUBISHI'));
        $this->assertFalse($this->spamShield->isTechnicalValue('randombrand'));
    }

    public function testIsGibberish(): void
    {
        // Clear gibberish
        $this->assertTrue($this->spamShield->isGibberish('QKvVOEdDeiAMgba'));
        $this->assertTrue($this->spamShield->isGibberish('vzsHrmroxOz'));

        // Human sentence
        $this->assertFalse($this->spamShield->isGibberish('Please contact me about pricing.'));

        // Technical token should not be treated as gibberish
        $this->assertFalse($this->spamShield->isGibberish('MDSDMDPV'));

        // Human name should be fine
        $this->assertFalse($this->spamShield->isGibberish('Ben Lee'));
    }

    public function testGibberishHitsFromValue(): void
    {
        $hits = $this->spamShield->gibberishHitsFromValue('Hello vzsHrmroxOz please contact QKvVOEdDeiAMgba tomorrow.');

        $this->assertGreaterThanOrEqual(2, $hits);
    }

    public function testAllowedValuesReduceGibberishHits(): void
    {
        // Text with one obvious gibberish token and one brand-like token
        $text = 'we need help with eyZZbvUC mitsubishi repair';

        $this->spamShield->setAllowedValues([]); // brand not allowed yet

        $hitsWithoutAllow = $this->spamShield->gibberishHitsFromValue($text);

        $this->spamShield->setAllowedValues(['MITSUBISHI']); // allow brand; it should be skipped from gibberish checks

        $hitsWithAllow = $this->spamShield->gibberishHitsFromValue($text);

        // Allowlist should never increase hits; usually drops by at least 0 or 1 depending on heuristics
        $this->assertGreaterThanOrEqual($hitsWithAllow, $hitsWithoutAllow);

        // And we still detect at least the gibberish token
        $this->assertGreaterThanOrEqual(1, $hitsWithAllow);
    }

    public function testAllowedValuesAffectsScorePathIndirectly(): void
    {
        $payload = [
            'full_name' => 'eyZZbvUC', // gibberish-looking name
            'email' => 'user@example.com',
            'phone' => '3178508930',
            'company_name' => 'mitsubishi', // will be treated as technical when allowed
            'company_zip_code' => '46203',
            'message' => 'Please quote spindle repair next week.',
        ];

        $meta = [
            'require_message' => true,
            'skip_dns_block_list' => true,
            'skip_mx_record_check' => true,
        ];

        // Run 1: no allowlist
        $s1 = new SpamShield();
        $s1->setStore(new ArrayStore());
        $s1->setAllowedValues([]);
        $r1 = $s1->score($payload, $meta);

        // Run 2: allowlist present (fresh instance/store -> no repetition penalty)
        $s2 = new SpamShield();
        $s2->setStore(new ArrayStore());
        $s2->setAllowedValues(['MITSUBISHI']);
        $r2 = $s2->score($payload, $meta);

        // Allowlisting should not increase score (usually lowers it slightly)
        $this->assertLessThanOrEqual($r1['score'], $r2['score'], 'Allowlist should not increase score');
    }

    public function testLooksLikeASentence(): void
    {
        $this->assertTrue($this->spamShield->looksLikeASentence('Looking for CNC training availability in November.'));

        $this->assertFalse($this->spamShield->looksLikeASentence('VCprntbWZpZgPm'));

        // too short / no sentence pattern
        $this->assertFalse($this->spamShield->looksLikeASentence('Hello'));

        // No spaces
        $this->assertFalse($this->spamShield->looksLikeASentence('Hello?No'));

        // No vowels
        $this->assertFalse($this->spamShield->looksLikeASentence('Ths s n sntnc'));
    }

    public function testShannonEntropy(): void
    {
        $low = $this->spamShield->shannonEntropy('aaaaabbbb'); // few unique chars
        $high = $this->spamShield->shannonEntropy('QKvVOEdDeiAMgba'); // many unique chars

        $this->assertLessThan(1.0, $low);
        $this->assertGreaterThan(3.0, $high);
    }

    public function testEmailHasMxRecord(): void
    {
        if (! \function_exists('checkdnsrr')) {
            $this->markTestSkipped('checkdnsrr not available');
        }

        // Known good MX (gmail.com)
        $ok = @$this->spamShield->emailHasMXRecord('user@gmail.com');

        if ($ok === false) {
            $this->markTestSkipped('DNS resolution unavailable in test environment');
        } else {
            $this->assertTrue($ok);
        }

        // Definitely invalid domain should return false
        $this->assertFalse($this->spamShield->emailHasMXRecord('user@invalid-tld.localdomain'));
    }

    public function testIsDisposable(): void
    {
        $this->assertFalse($this->spamShield->isDisposable('bar@example.com'));

        $this->assertTrue($this->spamShield->isDisposable('foo@mailinator.com'));

        // subdomain catch
        $this->assertTrue($this->spamShield->isDisposable('bar@x.yopmail.com'));
    }

    public function testListedOnDnsBlockList(): void
    {
        // Private/loopback should be ignored and return false
        $this->assertFalse($this->spamShield->listedOnDnsBlockList('127.0.0.1')); // loopback
        $this->assertFalse($this->spamShield->listedOnDnsBlockList('10.0.0.5')); // private
        $this->assertFalse($this->spamShield->listedOnDnsBlockList('192.168.1.10')); // private
        $this->assertFalse($this->spamShield->listedOnDnsBlockList('198.51.100.42')); // TEST-NET-2 reserved

        // IPv6 is skipped
        $this->assertFalse($this->spamShield->listedOnDnsBlockList('::1'));
    }

    public function testObviouslyFakePhone(): void
    {
        $this->assertTrue($this->spamShield->obviouslyFakePhone('0000000000'));
        $this->assertTrue($this->spamShield->obviouslyFakePhone('1111111111'));
        $this->assertTrue($this->spamShield->obviouslyFakePhone('0000000000'));
        $this->assertTrue($this->spamShield->obviouslyFakePhone('1111111111'));
        $this->assertTrue($this->spamShield->obviouslyFakePhone('5550000000'));

        $this->assertFalse($this->spamShield->obviouslyFakePhone('+1 407 555 8822'));
        $this->assertFalse($this->spamShield->obviouslyFakePhone('+1 (407) 555-8822'));
        $this->assertFalse($this->spamShield->obviouslyFakePhone('07400111222'));
    }

    public function testSuspectTopLevelDomains(): void
    {
        $this->assertTrue($this->spamShield->suspectTopLevelDomains('user@best-seo-links.shop'));

        $this->assertFalse($this->spamShield->suspectTopLevelDomains('user@example.com'));
    }

    public function testContainsPhishingTerms(): void
    {
        $this->assertTrue(
            $this->spamShield->containsAnyPhrase('Please verify your account at http://x.y/verify', [
                'verify your account','password reset',
            ]),
        );

        $this->assertFalse(
            $this->spamShield->containsAnyPhrase('Schedule a call next week about pricing.', [
                'verify your account','password reset',
            ]),
        );

        $result = $this->spamShield->score([
            'full_name' => 'IT Support',
            'email' => 'itsupport@example.com',
            'how_can_we_help_you' => 'Please verify your account here: http://example.com/verify',
        ], [
            'require_message' => true,
            'skip_mx_record_check' => true,
            'skip_dns_block_list' => true,
        ]);

        $this->assertContains('phishing_language', $result['reasons']);
        $this->assertTrue($result['is_spam']);
    }

    public function testContainsSpamTerms(): void
    {
        $this->assertTrue($this->spamShield->containsSpamTerms('We sell high DA dofollow backlinks!'));
        $this->assertTrue($this->spamShield->containsSpamTerms('We sell dofollow backlinks and guest post packages.'));

        $this->assertFalse($this->spamShield->containsSpamTerms('We need a spindle repair quote.'));
        $this->assertFalse($this->spamShield->containsSpamTerms('Requesting a quotation for spindle repair.'));
    }

    public function testUrlCount(): void
    {
        $this->assertSame(0, $this->spamShield->urlCount('No links here.'));
        $this->assertSame(1, $this->spamShield->urlCount('See https://example.org.'));
        $this->assertSame(2, $this->spamShield->urlCount('Go to http://a.test and also www.b.test now.'));
    }
}
