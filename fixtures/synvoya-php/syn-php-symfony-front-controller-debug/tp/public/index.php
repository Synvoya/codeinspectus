<?php
use App\Kernel;
use Symfony\Component\ErrorHandler\Debug;
require dirname(__DIR__).'/vendor/autoload.php';
Debug::enable();
$kernel = new Kernel('dev', true);
