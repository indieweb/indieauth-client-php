<?php

class NormalizeTest extends IndieAuthTestCase {

  public function testBareDomain() {
    $url = 'aaronpk.com';
    $normalized = IndieAuth\Client::normalizeMeURL($url);
    $this->assertEquals('http://aaronpk.com/', $normalized);
  }

  public function testNoSchemeWithPath() {
    $url = 'aaronpk.com/me';
    $normalized = IndieAuth\Client::normalizeMeURL($url);
    $this->assertEquals('http://aaronpk.com/me', $normalized);
  }

  public function testNoSlash() {
    $url = 'https://aaronpk.com';
    $normalized = IndieAuth\Client::normalizeMeURL($url);
    $this->assertEquals('https://aaronpk.com/', $normalized);
  }

  public function testRejectsInvalidScheme() {
    $url = 'mailto:me@example.com';
    $normalized = IndieAuth\Client::normalizeMeURL($url);
    $this->assertEquals(false, $normalized);
  }

  public function testAllowsQueryString() {
    $url = 'https://aaronpk.com?foo';
    $normalized = IndieAuth\Client::normalizeMeURL($url);
    $this->assertEquals('https://aaronpk.com/?foo', $normalized);
  }

  public function testRejectsFragment() {
    $url = 'https://aaronpk.com/#me';
    $normalized = IndieAuth\Client::normalizeMeURL($url);
    $this->assertEquals(false, $normalized);
  }

}

