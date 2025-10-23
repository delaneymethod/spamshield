# SpamShield

Lightweight, pluggable spam scoring for PHP forms. Works with Craft, ExpressionEngine, Laravel, or vanilla PHP.

## Install

```bash
composer require delaneymethod/spamshield
```

## Usage

Craft CMS with Freeform

```php
use Craft;
use craft\helpers\Json;
use delaneymethod\spamshield\SpamShield;
use Solspace\Freeform\Events\Forms\ValidationEvent;
use Solspace\Freeform\Form\Form;
use Solspace\Freeform\Freeform;
use Solspace\Freeform\Integrations\Single\FormMonitor\Providers\FormMonitorProvider;
use Solspace\Freeform\Library\DataObjects\SpamReason;
use yii\base\Event;
use yii\log\Logger;

Event::on(
    Form::class,
    Form::EVENT_BEFORE_VALIDATE,
    static function (ValidationEvent $event) {
        if (!$event->isValid) {
            return;
        }

        $settingsService = Freeform::getInstance()->settings;
        $settingsModel = $settingsService->getSettingsModel();
        if ($settingsModel->bypassSpamCheckOnLoggedInUsers && Craft::$app->getUser()->id) {
            return;
        }

        $form = $event->getForm();
        if (!$form->isLastPage()) {
            return;
        }

        $formMonitorProvider = Craft::$container->get(FormMonitorProvider::class);
        if ($formMonitorProvider->isRequestFromFormMonitor($form)) {
            return;
        }

        $submission = $form->getSubmission();

        $handle = $form->getHandle();

        $payload = $submission->getFormFieldValues();

        $meta = [
            'ip' => Craft::$app->getRequest()->getUserIP() ?? '',
            'field_handles' => [
                'extra_field_handle',
            ],
            'gibberish_word_length' => 6,
            'check_dns_block_lists' => true,
            'check_mx_record' => true,
            'minimum_message_words' => 5,
            'minimum_message_characters' => 300,
        ];

        $spamShield = new SpamShield();
        $spamShield->setAllowedValues(['ABB', 'KUKA']);
        $spamShield->setDnsBlockLists(['zen.spamhaus.org', 'bl.spamcop.net']);

        $result = $spamShield->score($payload, $meta);

        if ($result['is_spam']) {
            $form->markAsSpam(
                SpamReason::TYPE_GENERIC,
                'SpamShield test failed',
                Json::encode($result, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT)
            );
        }
    }
);
```

Vanilla PHP

```php
use delaneymethod\spamshield\SpamShield;

$meta = [
    'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
    'field_handles' => [
        'extra_field_handle',
    ],
    'gibberish_word_length' => 6,
    'check_dns_block_lists' => true,
    'check_mx_record' => true,
    'minimum_message_words' => 5,
    'minimum_message_characters' => 300,
];

$spamShield = new SpamShield();
$spamShield->setAllowedValues(['ABB', 'KUKA']);
$spamShield->setDnsBlockLists(['zen.spamhaus.org', 'bl.spamcop.net']);

$result = $spamShield->score($_POST, $meta);
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
