<?php
ini_set('error_reporting', E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

define('MODULE_PATH', __DIR__ . '/');
require MODULE_PATH . 'vendor/autoload.php';

use Classes\Parser;

$parser = new Parser();
$result = [];
try {
    $result = $parser->parse('/var/www/iexplore.exe');
} catch (Exception $e) {
    echo $e->getMessage();
}

echo '<pre>';
print_r($result);
echo '</pre>';