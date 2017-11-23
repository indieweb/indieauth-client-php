<?php

class HTMLTest extends IndieAuthTestCase {

  public function testExtractEndpointFromHTML() {
    $html = '<html><head><link rel="micropub" href="/micropub"></head><body><h1>Hello World</h1></body></html>';
    $result = $this->_invokeStaticMethod(IndieAuth\Client::class, 
      '_extractEndpointFromHTML', [$html, 'https://example.com/foo', 'micropub']);
    $this->assertEquals('https://example.com/micropub', $result);
  }

  public function testExtractRelativeEndpointFromHTML() {
    $html = '<html><head><link rel="micropub" href="micropub"></head><body><h1>Hello World</h1></body></html>';
    $result = $this->_invokeStaticMethod(IndieAuth\Client::class, 
      '_extractEndpointFromHTML', [$html, 'https://example.com/foo/', 'micropub']);
    $this->assertEquals('https://example.com/foo/micropub', $result);
  }

}
