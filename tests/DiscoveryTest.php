<?php

class DiscoveryTest extends IndieAuthTestCase {

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

  public function testExtractEmptyStringEndpointFromHTML() {
    $html = '<html><head><link rel="micropub" href=""></head><body><h1>Hello World</h1></body></html>';
    $result = $this->_invokeStaticMethod(IndieAuth\Client::class, 
      '_extractEndpointFromHTML', [$html, 'https://example.com/micropub', 'micropub']);
    $this->assertEquals('https://example.com/micropub', $result);
  }

  public function testExtractEndpointFromHeaders() {
    $headers = 'HTTP/1.1 200 Ok
Content-Type: text/html; charset=UTF-8
Cache-Control: no-cache
Link: <https://switchboard.p3k.io/>; rel="hub"
Link: </auth>; rel="authorization_endpoint"
Link: </micropub>; rel="micropub"
Link: </token>; rel="token_endpoint"';
    $result = $this->_invokeStaticMethod(IndieAuth\Client::class, 
      '_extractEndpointFromHeaders', [$headers, 'https://example.com/foo', 'micropub']);
    $this->assertEquals('https://example.com/micropub', $result);
  }  

  public function testExtractRelativeEndpointFromHeaders() {
    $headers = 'HTTP/1.1 200 Ok
Content-Type: text/html; charset=UTF-8
Cache-Control: no-cache
Link: <https://switchboard.p3k.io/>; rel="hub"
Link: </auth>; rel="authorization_endpoint"
Link: <micropub>; rel="micropub"
Link: </token>; rel="token_endpoint"';
    $result = $this->_invokeStaticMethod(IndieAuth\Client::class, 
      '_extractEndpointFromHeaders', [$headers, 'https://example.com/foo/', 'micropub']);
    $this->assertEquals('https://example.com/foo/micropub', $result);
  }  

  public function testExtractEmptyStringEndpointFromHeaders() {
    $headers = 'HTTP/1.1 200 Ok
Content-Type: text/html; charset=UTF-8
Cache-Control: no-cache
Link: <https://switchboard.p3k.io/>; rel="hub"
Link: <>; rel="authorization_endpoint"
Link: <>; rel="micropub"
Link: <>; rel="token_endpoint"';
    $result = $this->_invokeStaticMethod(IndieAuth\Client::class, 
      '_extractEndpointFromHeaders', [$headers, 'https://example.com/micropub', 'micropub']);
    $this->assertEquals('https://example.com/micropub', $result);
  }  

}
