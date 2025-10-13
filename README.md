# SpamShield

Lightweight, pluggable spam scoring for PHP forms. Works with Craft, ExpressionEngine, Laravel, or vanilla PHP.

## Install

```bash
composer require delaneymethod/spamshield
```

## Usage

```php
use delaneymethod\spamshield\SpamShield;
use delaneymethod\spamshield\stores\SessionStore;

SpamShield::setStore(new ApcuStore()); // or SessionStore (default store) or NullStore
SpamShield::setAllowedValues(['ABB', 'KUKA']);

$result = SpamShield::score($_POST, [
    'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
    'require_message' => true,
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
