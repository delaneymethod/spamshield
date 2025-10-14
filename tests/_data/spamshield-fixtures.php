<?php

/**
 * SpamShield
 * (c) 2025 Sean Delaney
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the delaneymethod/spamshield package.
 * See the LICENSE file in the project root for license details.
 */

return [
    // --- Legit submissions (should PASS) ---
    [
        'label' => 'Legit but no message',
        'payload' => [
            'firstname' => 'Cat',
            'lastname' => 'Cole',
            'email' => 'cat.astrophe207@gmail.com',
            'custom_field_1' => 'Test 1',
            'custom_field_2' => 'Test 2',
            'custom_field_3' => 'Test 3',
        ],
        'meta' => [
            'require_message' => false,
        ],
        'expect' => 'ham',
        'why' => 'Looks human.',
    ],
    [
        'label' => 'Legit US enquiry with part number',
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
            'require_message' => true,
        ],
        'expect' => 'ham',
        'why' => 'Normal sentences, technical token whitelisted, valid email/phone.',
    ],
    [
        'label' => 'Legit UK mobile, short but OK',
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
            'require_message' => true,
        ],
        'expect' => 'ham',
        'why' => 'Looks human, proper UK postcode & phone format.',
    ],
    [
        'label' => 'Quick quote, message optional',
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
            'require_message' => false,
            'minimum_message_characters' => 10,
            'minimum_message_words' => 2,
        ],
        'expect' => 'ham',
        'why' => 'Message not required for this form; other fields sane.',
    ],
    [
        'label' => 'Legit with URL (not spammy)',
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
            'require_message' => true,
        ],
        'expect' => 'ham',
        'why' => 'Sentence content, corporate domain, valid phone in E.164-ish.',
    ],
    [
        'label' => 'Very short but still human',
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
            'require_message' => true,
        ],
        'expect' => 'ham',
        'why' => 'Short but sentence-like and non-gibberish.',
    ],
    [
        'label' => 'Legit newsletter sign up',
        'payload' => [
            'email' => 'cat.astrophe207@gmail.com',
            'honeypot' => '',
        ],
        'meta' => [],
        'expect' => 'ham',
        'why' => 'Looks human.',
    ],
    [
        'label' => 'IP on private range (DNS Block List skipped)',
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
            'require_message' => true,
        ],
        'expect' => 'ham',
        'why' => 'Loopback with skip_dns_block_list=true should never hit DNS Block List.',
    ],
    [
        'label' => 'Repeated content hash (same message, diff email)',
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
            'require_message' => true,
        ],
        'expect' => 'ham',
        'why' => 'First time should pass.',
    ],
    // --- Spam patterns (should FAIL) ---
    [
        'label' => 'Spam newsletter sign up',
        'payload' => [
            'email' => 'cat.astrophe207@gmail.com',
            'honeypot' => 'MCBTyntpZgP',
        ],
        'meta' => [],
        'expect' => 'spam',
        'why' => 'Gibberish fields,',
    ],
    [
        'label' => 'Random gibberish + reused Gmail',
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
            'require_message' => true,
        ],
        'expect' => 'spam',
        'why' => 'Gibberish fields, short/no-sentence, weird zip.',
    ],
    [
        'label' => 'Same email repetition',
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
            'require_message' => true,
        ],
        'expect' => 'spam',
        'why' => 'Repeat email + gibberish should tip score over threshold.',
    ],
    [
        'label' => 'SEO bait link-drop',
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
            'require_message' => true,
        ],
        'expect' => 'spam',
        'why' => 'Spammy domain, nonsense phone, sales pitch link.',
    ],
    [
        'label' => 'Unicode/Cyrillic junk',
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
            'require_message' => true,
        ],
        'expect' => 'spam',
        'why' => 'Disposable domain + gibberish + sales language.',
    ],
    [
        'label' => 'Phishing-ish: ask for password reset',
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
            'require_message' => true,
        ],
        'expect' => 'spam',
        'why' => 'Link + social-engineering text, odd domain.',
    ],
    [
        'label' => 'Empty message on required form',
        'payload' => [
            'full_name' => 'James Doe',
            'email' => 'james@example.com',
            'phone' => '+1 555 902 8844',
            'company_name' => 'Example LLC',
            'company_zip_code' => '10001',
            'how_can_we_help_you' => '',
        ],
        'meta' => [
            'ip' => '203.0.113.15',
            'require_message' => true,
        ],
        'expect' => 'spam',
        'why' => 'Empty message with require_message=true should hit empty_message rule.',
    ],
    [
        'label' => 'All-caps random + US phone',
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
            'require_message' => true,
        ],
        'expect' => 'spam',
        'why' => 'Gibberish + short/no-sentence + weird zip.',
    ],
    [
        'label' => 'Disposable domain, looks humanish',
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
            'require_message' => true,
        ],
        'expect' => 'spam',
        'why' => 'Disposable domain should add enough to push near/over threshold.',
    ],
    [
        'label' => 'Repeated content hash (again)',
        'payload' => [
            'full_name' => 'Alice W',
            'email' => 'alicew@example.net',
            'phone' => '07700900222',
            'company_name' => 'AW Ltd',
            'company_zip_code' => 'AB1 2CD',
            'how_can_we_help_you' => 'Hello, this is a test message for spam filter repetition.',
        ],
        'meta' => [
            'ip' => '203.0.113.31',
            'require_message' => true,
        ],
        'expect' => 'spam',
        'why' => 'Second time within window should trigger repeat_content.',
    ],
    [
        'label' => 'Emoji/garbage + link dump',
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
            'require_message' => true,
        ],
        'expect' => 'spam',
        'why' => 'Disposable + nonsense + link spray.',
    ],
    [
        'label' => 'Homoglyph trick (looks like gmail but not)',
        'payload' => [
            'full_name' => 'Jane',
            'email' => 'jane@ɢmail.com', // small-cap G (U+0262) or similar
            'phone' => '07000000000',
            'company_name' => 'Jane Co',
            'company_zip_code' => 'W1A 1HQ',
            'how_can_we_help_you' => 'Please contact me.',
        ],
        'meta' => [
            'ip' => '198.51.100.41',
            'require_message' => true,
        ],
        'expect' => 'spam',
        'why' => 'Bad domain (no MX record), weird characters.',
    ],
    [
        'label' => 'Massaged gibberish names but human message',
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
            'require_message' => true,
        ],
        'expect' => 'spam',
        'why' => 'Gibberish fields outweigh a single normal sentence.',
    ],
];
