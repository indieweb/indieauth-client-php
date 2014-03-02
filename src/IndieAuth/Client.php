<?php
namespace IndieAuth;

class Client {

  private static $_headers = null;
  private static $_body = null;

  private static function _domainIsValid($domain) {
    $url = parse_url($domain);

    if($url == false
      || !array_key_exists('scheme', $url)
      || !in_array($url['scheme'], array('http','https'))
      || !array_key_exists('host', $url)
      || (array_key_exists('path', $url) && $url['path'] != '/')  // must be top-level domain, no paths
    ) {
      // Invalid domain
      return false;
    }

    return true;
  }

  private static function _fetchHead($url) {
    if(self::$_headers) {
      return self::$_headers;
    } else {
      $ch = curl_init($url);
      self::_setUserAgent($ch);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
      curl_setopt($ch, CURLOPT_HEADER, true);
      curl_setopt($ch, CURLOPT_NOBODY, true);
      self::$_headers = curl_exec($ch);
      return self::$_headers;
    }
  }

  private static function _fetchBody($url) {
    if(self::$_body) {
      return self::$_body;
    } else {
      $ch = curl_init($url);
      self::_setUserAgent($ch);
      curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      self::$_body = curl_exec($ch);
      return self::$_body;
    }
  }

  private static function _discoverEndpoint($domain, $name) {
    if(!self::_domainIsValid($domain))
      return null;

    // First check the HTTP headers for an authorization endpoint
    $headerString = self::_fetchHead($domain);
    $headers = \IndieWeb\http_rels($headerString);
    
    if($headers && array_key_exists($name, $headers)) {
      return $headers[$name][0];
    }

    // If not found, check the body for a rel value
    $html = self::_fetchBody($domain);

    $parser = new \mf2\Parser($html);
    $data = $parser->parse();

    if($data && array_key_exists('rels', $data)) {
      if(array_key_exists($name, $data['rels'])) {
        return $data['rels'][$name][0];
      }
    }

    return false;
  }

  public static function discoverAuthorizationEndpoint($domain) {
    return self::_discoverEndpoint($domain, 'authorization_endpoint');
  }

  public static function discoverTokenEndpoint($domain) {
    return self::_discoverEndpoint($domain, 'token_endpoint');
  }

  public static function discoverMicropubEndpoint($domain) {
    return self::_discoverEndpoint($domain, 'micropub');
  }

  // Optional helper method to generate a state parameter. You can just as easily do this yourself some other way.
  public static function generateStateParameter() {
    return mt_rand(1000000, 9999999);
  }

  // Build the authorization URL for the given domain and endpoint
  public static function buildAuthorizationURL($authorizationEndpoint, $domain, $redirectURI, $clientID, $state, $scope='') {
    $url = parse_url($authorizationEndpoint);

    $params = array();
    if(array_key_exists('query', $url)) {
      parse_str($url['query'], $params);
    }

    $params['me'] = $domain;
    $params['redirect_uri'] = $redirectURI;
    $params['client_id'] = $clientID;
    $params['state'] = $state;
    if($scope) $params['scope'] = $scope;

    $url['query'] = http_build_query($params);

    return self::build_url($url);
  }

  public static function build_url($parsed_url) { 
    $scheme   = isset($parsed_url['scheme']) ? $parsed_url['scheme'] . '://' : ''; 
    $host     = isset($parsed_url['host']) ? $parsed_url['host'] : ''; 
    $port     = isset($parsed_url['port']) ? ':' . $parsed_url['port'] : ''; 
    $user     = isset($parsed_url['user']) ? $parsed_url['user'] : ''; 
    $pass     = isset($parsed_url['pass']) ? ':' . $parsed_url['pass']  : ''; 
    $pass     = ($user || $pass) ? "$pass@" : ''; 
    $path     = isset($parsed_url['path']) ? $parsed_url['path'] : ''; 
    $query    = isset($parsed_url['query']) ? '?' . $parsed_url['query'] : ''; 
    $fragment = isset($parsed_url['fragment']) ? '#' . $parsed_url['fragment'] : ''; 
    return "$scheme$user$pass$host$port$path$query$fragment"; 
  } 

  // Used by clients to get an access token given an auth code
  public static function getAccessToken($tokenEndpoint, $code, $domain, $redirectURI, $clientID, $state, $debug=false) {
    $ch = curl_init();
    self::_setUserAgent($ch);
    curl_setopt($ch, CURLOPT_URL, $tokenEndpoint);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ch, CURLOPT_POST, TRUE);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(array(
      'me' => $domain,
      'code' => $code,
      'redirect_uri' => $redirectURI,
      'state' => $state,
      'client_id' => $clientID
    )));
    $response = curl_exec($ch);

    $auth = array();
    parse_str($response, $auth);

    if($debug) {
      return array(
        'auth' => $auth,
        'response' => $response,
        'response_code' => curl_getinfo($ch, CURLINFO_HTTP_CODE)
      );
    } else {
      return $auth;
    }
  }

  // Used by a token endpoint to verify the auth code
  public static function verifyIndieAuthCode($authorizationEndpoint, $code, $domain, $redirectURI, $clientID, $state, $debug=false) {
    $ch = curl_init();
    self::_setUserAgent($ch);
    curl_setopt($ch, CURLOPT_URL, $authorizationEndpoint);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ch, CURLOPT_POST, TRUE);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(array(
      'code' => $code,
      'redirect_uri' => $redirectURI,
      'state' => $state,
      'client_id' => $clientID
    )));
    $response = curl_exec($ch);

    $auth = array();
    parse_str($response, $auth);

    if($debug) {
      return array(
        'auth' => $auth,
        'response' => $response,
        'response_code' => curl_getinfo($ch, CURLINFO_HTTP_CODE)
      );
    } else {
      return $auth;
    }
  }

  private static function _setUserAgent(&$ch) {
    // Unfortunately I've seen a bunch of websites return different content when the user agent is set to something like curl or other server-side libraries, so we have to pretend to be a browser to successfully get the real HTML
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.57 Safari/537.36');
  }

}
