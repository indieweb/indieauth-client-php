<?php
const TESTING = true;
require __DIR__ . '/../vendor/autoload.php';

use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class IndieAuthTestCase extends TestCase {

  protected function _invokeMethod(&$object, $methodName, $params=[]) {
    $reflection = new \ReflectionClass(get_class($object));
    $method = $reflection->getMethod($methodName);
    $method->setAccessible(true);
    return $method->invokeArgs($object, $params);
  }

  protected function _invokeStaticMethod($class, $methodName, $params=[]) {
    $reflection = new \ReflectionClass($class);
    $method = $reflection->getMethod($methodName);
    $method->setAccessible(true);
    return $method->invokeArgs(null, $params);
  }

}
