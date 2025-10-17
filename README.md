# SpamShield

Lightweight, pluggable spam scoring for PHP forms. Works with Craft, ExpressionEngine, Laravel, or vanilla PHP.

## Install

```bash
composer require delaneymethod/spamshield
```

## Usage

```php
use delaneymethod\spamshield\SpamShield;

SpamShield::setAllowedValues(['ABB', 'KUKA']);

$result = SpamShield::score($_POST, [
    'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
    'require_message' => true,
    'gibberish_keys' => ['my_field_handle'],
    'skip_dns_block_list' => true,
    'skip_mx_record_check' => true,
    'minimum_message_words' => 5,
    'minimum_message_characters' => 300,
]);

if ($result['is_spam']) {
    // block or fake success
}
```

### Tests

```php
composer install
composer run fix
composer run ci
```
