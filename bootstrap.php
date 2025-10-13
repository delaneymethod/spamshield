<?php

declare(strict_types=1);

ob_start();

ini_set('session.use_cookies', '0');
ini_set('session.use_only_cookies', '0');
ini_set('session.cache_limiter', '');

if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_id('phpunit');
    @session_start();
}

require './vendor/autoload.php';
