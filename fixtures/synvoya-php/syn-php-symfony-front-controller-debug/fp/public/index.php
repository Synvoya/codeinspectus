<?php
use App\Kernel;
use Symfony\Component\ErrorHandler\Debug;
if ($_SERVER['APP_DEBUG']) {
    Debug::enable();
}
$kernel = new Kernel($_SERVER['APP_ENV'], (bool) $_SERVER['APP_DEBUG']);
