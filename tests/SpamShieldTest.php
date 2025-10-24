<?php

/**
 * SpamShield
 * (c) 2025 Sean Delaney
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the delaneymethod/spamshield package.
 * See the LICENSE file in the project root for license details.
 */

namespace delaneymethod\spamshield\tests;

use delaneymethod\spamshield\SpamShield;
use PHPUnit\Framework\TestCase;

class SpamShieldTest extends TestCase
{
    /**
     * @var SpamShield
     */
    private SpamShield $spamShield;

    /**
     * @return void
     */
    protected function setUp(): void
    {
        $this->spamShield = new SpamShield();
    }

    /**
     * @return void
     */
    public function testFixtures(): void
    {
        foreach ($this->getTestFixture() as $fixture) {
            $meta = $fixture['meta'] ?? [];
            $meta['check_dns_block_lists'] = true;
            $meta['check_mx_record'] = true;
            $meta['gibberish_word_minimum_length'] = 5;

            $result = $this->spamShield->score($fixture['payload'], $meta);

            $message = 'Payload: ' . json_encode($fixture['payload'], \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE) . ' | Report: ' . json_encode($result, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE);

            if ($fixture['contains_spam']) {
                $this->assertTrue($result['is_spam']);
            } else {
                $this->assertFalse($result['is_spam'], $message);
            }
        }
    }

    /**
     * @return void
     */
    public function testSetAllowedTerms(): void
    {
        $this->assertSame([], $this->spamShield->allowedTerms);

        $this->spamShield->setAllowedTerms(['MITSUBISHI', 'FANUC']);

        $this->assertSame(['MITSUBISHI', 'FANUC'], $this->spamShield->allowedTerms);
    }

    /**
     * @return void
     */
    public function testAllowedValues(): void
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
            'check_dns_block_lists' => true,
            'check_mx_record' => true,
        ];

        $spamShield1 = new SpamShield();
        $spamShield1->setAllowedTerms([]);
        $result1 = $spamShield1->score($payload, $meta);

        $spamShield2 = new SpamShield();
        $spamShield2->setAllowedTerms(['MITSUBISHI']);
        $result2 = $spamShield2->score($payload, $meta);

        $this->assertLessThanOrEqual($result1['score'], $result2['score'], 'Allowlist should not increase score');
    }

    /**
     * @return void
     */
    public function testEmailHasMxRecord(): void
    {
        if (!\function_exists('checkdnsrr')) {
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

    /**
     * @return void
     */
    public function testIsDisposable(): void
    {
        $this->assertFalse($this->spamShield->isDisposable('bar@example.com'));

        $this->assertTrue($this->spamShield->isDisposable('foo@mailinator.com'));

        // subdomain catch
        $this->assertTrue($this->spamShield->isDisposable('bar@x.yopmail.com'));
    }

    /**
     * @return void
     */
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

    /**
     * @return void
     */
    public function testIsFakePhoneNumber(): void
    {
        $this->assertTrue($this->spamShield->isFakePhoneNumber('0000000000'));
        $this->assertTrue($this->spamShield->isFakePhoneNumber('1111111111'));
        $this->assertTrue($this->spamShield->isFakePhoneNumber('0000000000'));
        $this->assertTrue($this->spamShield->isFakePhoneNumber('1111111111'));
        $this->assertTrue($this->spamShield->isFakePhoneNumber('5550000000'));

        $this->assertFalse($this->spamShield->isFakePhoneNumber('+1 407 555 8822'));
        $this->assertFalse($this->spamShield->isFakePhoneNumber('+1 (407) 555-8822'));
        $this->assertFalse($this->spamShield->isFakePhoneNumber('07400111222'));
    }

    /**
     * @return void
     */
    public function testSuspectTopLevelDomains(): void
    {
        $this->assertTrue($this->spamShield->hasSuspectTopLevelDomain('user@best-seo-links.shop'));

        $this->assertFalse($this->spamShield->hasSuspectTopLevelDomain('user@example.com'));
    }

    /**
     * @return void
     */
    public function testContainsPhishingTerms(): void
    {
        $this->assertTrue($this->spamShield->containsPhishingTerms('Please verify your account at http://x.y/verify'));

        $this->assertFalse($this->spamShield->containsPhishingTerms('Schedule a call next week about pricing.'));

        $result = $this->spamShield->score([
            'full_name' => 'IT Support',
            'email' => 'itsupport@example.com',
            'how_can_we_help_you' => 'Please verify your account here: http://example.com/verify',
        ], [
            'check_mx_record' => true,
            'check_dns_block_lists' => true,
        ]);

        $this->assertEquals('contains_phishing_link_combo', $result['reasons']['how_can_we_help_you']);
        $this->assertTrue($result['is_spam']);
    }

    /**
     * @return void
     */
    public function testContainsSpamTerms(): void
    {
        $this->assertTrue($this->spamShield->containsSpamTerms('We sell high DA dofollow backlinks!'));
        $this->assertTrue($this->spamShield->containsSpamTerms('We sell dofollow backlinks and guest post packages.'));

        $this->assertFalse($this->spamShield->containsSpamTerms('We need a spindle repair quote.'));
        $this->assertFalse($this->spamShield->containsSpamTerms('Requesting a quotation for spindle repair.'));
    }

    /**
     * @return void
     */
    public function testUrlCount(): void
    {
        $this->assertSame(0, $this->spamShield->urlCount('No links here.'));
        $this->assertSame(1, $this->spamShield->urlCount('See https://example.org.'));
        $this->assertSame(2, $this->spamShield->urlCount('Go to http://a.test and also www.b.test now.'));
    }

    /**
     * @return array
     */
    private function getTestFixture(): array
    {
        return [
            // --- Human (should PASS) ---
            [
                'payload' => [
                    'firstname' => 'cat',
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'message' => 'I love this website',
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'message' => "wouldn't",
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'message' => "shouldn't",
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'message' => "industry's",
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'message' => "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.",
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'lastname' => "O'Connor",
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'full_name' => "Kevin O'Connor",
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'lastname' => 'Fanneran',
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'fullname' => 'Jason Moloney',
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'lastname' => 'DeAngelo',
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'fullname' => 'Peter DeAngelo',
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'surname' => 'LeBron',
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'phone' => '020 7946 0018',
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'message' => 'typesetting',
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'message' => 'essentially',
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'firstname' => 'Cat',
                    'lastname' => 'Cole',
                    'email' => 'cat.cole@gmail.com',
                    'custom_field_1' => 'Test 1',
                    'custom_field_2' => 'Test 2',
                    'custom_field_3' => 'Test 3',
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'full_name' => 'Jose Davidi',
                    'email' => 'jdavidi@gmail.com',
                    'phone' => '3797160043',
                    'company_name' => 'Swiss Cheese Co',
                    'company_zip_code' => '48881',
                    'how_can_we_help_you' => 'Our MDSDMDPV 310080 Mitsubishi drive needs rebuilt. Can you quote turnaround?',
                ],
                'meta' => [
                    'ip' => '198.51.100.25',
                ],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'full_name' => 'Amelia Clarke',
                    'email' => 'amelia.clarke@example.co.uk',
                    'phone' => '07400111222',
                    'company_name' => 'Clarke Engineering',
                    'company_zip_code' => 'SW1A 1AA',
                    'how_can_we_help_you' => 'Looking for CNC training availability in November.',
                ],
                'meta' => [
                    'ip' => '203.0.113.54',
                ],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'full_name' => 'Joseph Johnson',
                    'email' => 'jbjohnson@piicnc.com',
                    'phone' => '3178508930',
                    'company_name' => 'Paramount Industrial',
                    'company_zip_code' => '46203',
                    'how_can_we_help_you' => '',
                ],
                'meta' => [
                    'ip' => '203.0.113.21',
                    'minimum_message_characters' => 10,
                    'minimum_message_words' => 2,
                ],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'full_name' => 'Priya Nair',
                    'email' => 'priya.nair@kuka-automation.in',
                    'phone' => '+1 (407) 555-8822',
                    'company_name' => 'KUKA Automation India',
                    'company_zip_code' => '32801',
                    'how_can_we_help_you' => 'Please review our RFP at https://example.org/rfp.pdf and confirm scope.',
                ],
                'meta' => [
                    'ip' => '198.51.100.90',
                ],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'full_name' => 'Ben Lee',
                    'email' => 'ben@leemetal.com',
                    'phone' => '+44 7700 900111',
                    'company_name' => 'Lee Metal',
                    'company_zip_code' => 'M1 2AB',
                    'how_can_we_help_you' => 'Quote please for spindle repair.',
                ],
                'meta' => [
                    'ip' => '203.0.113.12',
                ],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'email' => 'cat.astrophe207@gmail.com',
                    'honeypot' => '',
                ],
                'meta' => [],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'full_name' => 'Local Tester',
                    'email' => 'tester@local.dev',
                    'phone' => '07400900333',
                    'company_name' => 'Dev Env',
                    'company_zip_code' => 'AB1 2CD',
                    'how_can_we_help_you' => 'Testing locally, please ignore.',
                ],
                'meta' => [
                    'ip' => '127.0.0.1',
                ],
                'contains_spam' => false,
            ],
            [
                'payload' => [
                    'full_name' => 'Tom R',
                    'email' => 'tomr@example.net',
                    'phone' => '07700900111',
                    'company_name' => 'TR Ltd',
                    'company_zip_code' => 'AB1 2CD',
                    'how_can_we_help_you' => 'Hello, this is a test message for spam filter repetition.',
                ],
                'meta' => [
                    'ip' => '203.0.113.31',
                ],
                'contains_spam' => false,
            ],
            // --- Spam (should FAIL) ---
            [
                'payload' => [
                    'full_name' => 'MCBTyJZoy',
                    'email' => 'tunivuya94@gmail.com',
                    'phone' => '2070301291',
                    'company_name' => 'bIEFbZls',
                    'company_zip_code' => 'abAQAIajhVVXo',
                    'how_can_we_help_you' => 'VCprntbWZpZgPm',
                ],
                'meta' => [
                    'ip' => '203.0.113.10',
                ],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'full_name' => 'kHSckpHEAYjO',
                    'email' => 'tunivuya94@gmail.com', // repeat
                    'phone' => '5656943861',
                    'company_name' => 'oMyOJvwmVKXCyjZ',
                    'company_zip_code' => 'DVsLTYPVtz',
                    'how_can_we_help_you' => 'OlSbMCboVCmPu',
                ],
                'meta' => [
                    'ip' => '203.0.113.11',
                ],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'full_name' => 'Content Outreach',
                    'email' => 'outreach@best-seo-links.shop',
                    'phone' => '0000000000',
                    'company_name' => 'TopRankers',
                    'company_zip_code' => 'N/A',
                    'how_can_we_help_you' => 'We can place dofollow backlinks on Forbes & CNN. See https://best-seo-links.shop/offer.',
                ],
                'meta' => [
                    'ip' => '198.51.100.77',
                ],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'full_name' => 'ВыгоднаяСделка',
                    'email' => 'promo@yopmail.com',
                    'phone' => '8337608946',
                    'company_name' => 'ЛучшаяКомпания',
                    'company_zip_code' => 'vzsHrmroxOz',
                    'how_can_we_help_you' => 'Купи сейчас! Скидка 90% #@@',
                ],
                'meta' => [
                    'ip' => '203.0.113.60',
                ],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'full_name' => 'IT Support',
                    'email' => 'itsupport@corp-mailer.com',
                    'phone' => '5551231234',
                    'company_name' => 'Support',
                    'company_zip_code' => '00000',
                    'how_can_we_help_you' => 'Please verify your account password here: http://corp-mailer.com/verify',
                ],
                'meta' => [
                    'ip' => '198.51.100.40',
                ],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'full_name' => 'OVdFPmUF',
                    'email' => 'xilojeju237@gmail.com',
                    'phone' => '4079079846',
                    'company_name' => 'QKvVOEdDeiAMgba',
                    'company_zip_code' => 'wfdlzEuvEEZiSDY',
                    'how_can_we_help_you' => 'mQJYspqJugGtnXRt',
                ],
                'meta' => [
                    'ip' => '203.0.113.16',
                ],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'full_name' => 'Sarah P',
                    'email' => 'sarahp@mailinator.com',
                    'phone' => '07400999123',
                    'company_name' => 'Self',
                    'company_zip_code' => 'EC1A 1BB',
                    'how_can_we_help_you' => 'Hi can you contact me about pricing?',
                ],
                'meta' => [
                    'ip' => '203.0.113.19',
                ],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'full_name' => 'Free Money!!!',
                    'email' => 'promo@tempmail.com',
                    'phone' => '9999999999',
                    'company_name' => '💰💰💰',
                    'company_zip_code' => '0000',
                    'how_can_we_help_you' => 'WIN BIG NOW 👉 https://spam.biz http://spam.co free gift!!!',
                ],
                'meta' => [
                    'ip' => '203.0.113.200',
                ],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'full_name' => 'LlCSEgInkFNufMQ',
                    'email' => 'ops@manufacture.us',
                    'phone' => '8337608946',
                    'company_name' => 'eyZZbvUC',
                    'company_zip_code' => 'vzsHrmroxOz',
                    'how_can_we_help_you' => 'We need a call about training schedule and costs next week.',
                ],
                'meta' => [
                    'ip' => '203.0.113.66',
                ],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'full_name' => 'LlCSEgInkFNufMQ',
                ],
                'meta' => [
                    'ip' => '203.0.113.66',
                ],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'firstname' => 'fdghdfhdfhdgf',
                    'lastname' => 'fdgh fghfgh',
                    'tel' => '01234567890',
                    'email' => 'sdfsdfds@ghjhkf.hh',
                    'message' => 'fdgh df hdfasdd kjlhjk jkj asdd hdgf',
                ],
                'meta' => [],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'firstname' => 'asd',
                ],
                'meta' => [],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'firstname' => 'zzzzzzz',
                ],
                'meta' => [],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'firstname' => 'asdasdasd',
                ],
                'meta' => [],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'firstname' => 'zxcvwerjasc',
                ],
                'meta' => [],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'firstname' => 'vzsHrmroxOz',
                ],
                'meta' => [],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'firstname' => 'eyZZbvUC',
                ],
                'meta' => [],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'firstname' => 'LlCSEgInkFNufMQ',
                ],
                'meta' => [],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'firstname' => 'fdghdfhdfhdgf',
                ],
                'meta' => [],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'firstname' => 'bcdcdfghjklmnp',
                ],
                'meta' => [],
                'contains_spam' => true,
            ],
            [
                'payload' => [
                    'message' => 'Please verify your account at https://ex.amp/le',
                ],
                'meta' => [],
                'contains_spam' => true,
            ],
        ];
    }
}
