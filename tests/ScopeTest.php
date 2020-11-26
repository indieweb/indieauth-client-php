<?php

class ScopeTest extends IndieAuthTestCase {

  public function testFindsProfileScopes() {
    $scopes = IndieAuth\Client::parseNonProfileScopes('profile email create update');
    $this->assertTrue(is_array($scopes));
    $this->assertContains('create', $scopes);
    $this->assertContains('update', $scopes);
    $this->assertNotContains('profile', $scopes);
    $this->assertNotContains('email', $scopes);
  }

  public function testWorksWithEmptyScope() {
    $scopes = IndieAuth\Client::parseNonProfileScopes('');
    $this->assertTrue(is_array($scopes));
    $this->assertNotContains('profile', $scopes);
    $this->assertNotContains('email', $scopes);
  }

  public function testAcceptsFalseInput() {
    $scopes = IndieAuth\Client::parseNonProfileScopes(false);
    $this->assertTrue(is_array($scopes));
    $this->assertNotContains('profile', $scopes);
    $this->assertNotContains('email', $scopes);
  }

  public function testExcludesOneScope() {
    $scopes = IndieAuth\Client::parseNonProfileScopes('profile');
    $this->assertTrue(is_array($scopes));
    $this->assertNotContains('profile', $scopes);
  }

  public function testIncludesOneScope() {
    $scopes = IndieAuth\Client::parseNonProfileScopes('create');
    $this->assertTrue(is_array($scopes));
    $this->assertContains('create', $scopes);
  }

}
