<?php

// Serves canned responses keyed by "METHOD url" and records every request.
class FakeTransport implements \p3k\HTTP\Transport {

  public $requests = [];
  private $responses = [];

  public function respond($method, $url, $code, $body, $contentType='text/html') {
    $this->responses[$method . ' ' . $url] = [$code, $body, $contentType];
  }

  public function json($method, $url, $data) {
    $this->respond($method, $url, 200, json_encode($data), 'application/json');
  }

  public function set_timeout($timeout) {}
  public function set_max_redirects($max) {}

  public function get($url, $headers=[]) { return $this->answer('GET', $url, null); }
  public function post($url, $body, $headers=[]) { return $this->answer('POST', $url, $body); }
  public function put($url, $body, $headers=[]) { return $this->answer('PUT', $url, $body); }
  public function head($url, $headers=[]) {
    $response = $this->answer('HEAD', $url, null, 'GET');
    unset($response['body']);
    return $response;
  }

  private function answer($method, $url, $body, $fallback=null) {
    $this->requests[] = [$method, $url, $body];
    $found = $this->responses[$method . ' ' . $url] ?? ($fallback ? ($this->responses[$fallback . ' ' . $url] ?? null) : null);
    list($code, $responseBody, $contentType) = $found ?: [404, 'not found', 'text/plain'];
    return [
      'code' => $code,
      'header' => "HTTP/1.1 $code\r\nContent-Type: $contentType",
      'body' => $responseBody,
      'error' => '',
      'error_description' => '',
      'url' => $url,
      'debug' => '',
    ];
  }
}
