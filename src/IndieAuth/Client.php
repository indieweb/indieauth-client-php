<?php
namespace IndieAuth;
use BarnabyWalters\Mf2;

define('RANDOM_BYTE_COUNT', 8);

class Client {

  private static $_headers = array();
  private static $_body = array();

  private static function _urlIsValid($url) {
    $url = parse_url($url);

    if($url == false
      || !array_key_exists('scheme', $url)
      || !in_array($url['scheme'], array('http','https'))
      || !array_key_exists('host', $url)
    ) {
      // Invalid url
      return false;
    }

    return true;
  }

  private static function _fetchHead($url) {
    if(array_key_exists($url, self::$_headers)) {
      return self::$_headers[$url];
    } else {
      $ch = curl_init($url);
      self::_setUserAgent($ch);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
      curl_setopt($ch, CURLOPT_HEADER, true);
      curl_setopt($ch, CURLOPT_NOBODY, true);
      self::$_headers[$url] = curl_exec($ch);
      return self::$_headers[$url];
    }
  }

  private static function _fetchBody($url) {
    if(array_key_exists($url, self::$_body)) {
      return self::$_body[$url];
    } else {
      $ch = curl_init($url);
      self::_setUserAgent($ch);
      curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      self::$_body[$url] = curl_exec($ch);
      return self::$_body[$url];
    }
  }

  private static function _discoverEndpoint($url, $name) {
    if(!self::_urlIsValid($url))
      return null;

    // First check the HTTP headers for an authorization endpoint
    $headerString = self::_fetchHead($url);
    $headers = \IndieWeb\http_rels($headerString);

    if(isset($headers[$name][0]) && $headers[$name][0]) {
      return \Mf2\resolveUrl($url, $headers[$name][0]);
    }

    // If not found, check the body for a rel value
    $html = self::_fetchBody($url);

    $parser = new \Mf2\Parser($html);
    $data = $parser->parse();

    if(isset($data['rels'][$name][0]) && $data['rels'][$name][0]) {
      return \Mf2\resolveUrl($url, $data['rels'][$name][0]);
    }

    return false;
  }

  public static function discoverAuthorizationEndpoint($url) {
    return self::_discoverEndpoint($url, 'authorization_endpoint');
  }

  public static function discoverTokenEndpoint($url) {
    return self::_discoverEndpoint($url, 'token_endpoint');
  }

  public static function discoverMicropubEndpoint($url) {
    return self::_discoverEndpoint($url, 'micropub');
  }

  // Optional helper method to generate a state parameter. You can just as easily do this yourself some other way.
  public static function generateStateParameter() {
    if(function_exists('random_bytes')) {
      $bytes = random_bytes(RANDOM_BYTE_COUNT);
    } elseif(function_exists('openssl_random_pseudo_bytes')){
      $bytes = openssl_random_pseudo_bytes(RANDOM_BYTE_COUNT);
    } else {
      $bytes = '';
      for($i=0, $bytes=''; $i < RANDOM_BYTE_COUNT; $i++) {
        $bytes .= chr(mt_rand(0, 255));
      }
    }
    return bin2hex($bytes);
  }

  // Build the authorization URL for the given url and endpoint
  public static function buildAuthorizationURL($authorizationEndpoint, $me, $redirectURI, $clientID, $state, $scope='') {
    $url = parse_url($authorizationEndpoint);

    $params = array();
    if(array_key_exists('query', $url)) {
      parse_str($url['query'], $params);
    }

    $params['me'] = $me;
    $params['redirect_uri'] = $redirectURI;
    $params['client_id'] = $clientID;
    $params['state'] = $state;
    if($scope) {
      $params['scope'] = $scope;
      $params['response_type'] = 'code';
    } else {
      $params['response_type'] = 'id';
    }

    $url['query'] = http_build_query($params);

    return self::build_url($url);
  }

  // Input: Any URL or string like "aaronparecki.com"
  // Output: Normlized URL (default to http if no scheme, default "/" path)
  //         or return false if not a valid URL (has query string params, etc)
  public static function normalizeMeURL($url) {
    $me = parse_url($url);

    if(array_key_exists('path', $me) && $me['path'] == '')
      return false;

    // parse_url returns just "path" for naked domains, so
    // move that into the "host" instead
    if(count($me) == 1 && array_key_exists('path', $me)) {
      $me['host'] = $me['path'];
      unset($me['path']);
    }

    if(!array_key_exists('scheme', $me))
      $me['scheme'] = 'http';

    if(!array_key_exists('path', $me))
      $me['path'] = '/';

    // Invalid scheme
    if(!in_array($me['scheme'], array('http','https')))
      return false;

    // query and fragment not allowed
    if(array_key_exists('query', $me) || array_key_exists('fragment', $me))
      return false;

    return self::build_url($me);
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
  public static function getAccessToken($tokenEndpoint, $code, $me, $redirectURI, $clientID, $debug=false) {
    $ch = curl_init();
    self::_setUserAgent($ch);
    curl_setopt($ch, CURLOPT_URL, $tokenEndpoint);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ch, CURLOPT_POST, TRUE);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(array(
      'grant_type' => 'authorization_code',
      'me' => $me,
      'code' => $code,
      'redirect_uri' => $redirectURI,
      'client_id' => $clientID
    )));
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'Accept: application/json, application/x-www-form-urlencoded;q=0.8'
    ));
    $response = curl_exec($ch);

    $auth = json_decode($response, true);
    if(!$auth) {
      // Parse as form-encoded for fallback support
      $auth = array();
      parse_str($response, $auth);
    }

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
  public static function verifyIndieAuthCode($authorizationEndpoint, $code, $me, $redirectURI, $clientID, $debug=false) {
    $ch = curl_init();
    self::_setUserAgent($ch);
    curl_setopt($ch, CURLOPT_URL, $authorizationEndpoint);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ch, CURLOPT_POST, TRUE);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(array(
      'code' => $code,
      'redirect_uri' => $redirectURI,
      'client_id' => $clientID
    )));
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'Accept: application/json, application/x-www-form-urlencoded;q=0.8'
    ));
    $response = curl_exec($ch);

    $auth = json_decode($response, true);
    if(!$auth) {
      // Parse as form-encoded for fallback support
      $auth = array();
      parse_str($response, $auth);
    }

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

  public static function representativeHCard($url) {
    $html = self::_fetchBody($url);
    $parser = new \Mf2\Parser($html, $url);
    $data = $parser->parse();
    $hCards = Mf2\findMicroformatsByType($data, 'h-card');

    // http://microformats.org/wiki/representative-hcard-parsing
    foreach($hCards as $item) {
      if(Mf2\hasProp($item, 'url') && Mf2\hasProp($item, 'uid')
        && in_array($url, $item['properties']['url'])
        && in_array($url, $item['properties']['uid'])) {
        return $item;
      }
    }

    return false;
  }

  private static function _setUserAgent(&$ch) {
    // Unfortunately I've seen a bunch of websites return different content when the user agent is set to something like curl or other server-side libraries, so we have to pretend to be a browser to successfully get the real HTML
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.57 Safari/537.36');
  }

}
