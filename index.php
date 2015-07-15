<?php
ini_set('error_reporting', E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

define('MODULE_PATH', __DIR__ . '/');
require MODULE_PATH . 'vendor/autoload.php';

use Classes\Parser;

Parser::main();