<?php
namespace IndieAuth;

define('RANDOM_BYTE_COUNT', 8);

class Client {

  private static $_headers = array();
  private static $_body = array();
  private static $_parsed = null;
  private static $_parsedHash = null;

  public static $http;

  public static $clientID;
  public static $redirectURL;

  // Handles everything you need to start the authorization process.
  // Discovers the user's auth endpoints, generates and stores a state in the session.
  // Returns an authorization URL or an error array.
  public static function begin($url, $scope=false) {
    if(!isset(self::$clientID) || !isset(self::$redirectURL)) {
      return [false, [
        'error' => 'not_configured',
        'error_description' => 'Before you can begin, you need to configure the clientID and redirectURL of the IndieAuth client'
      ]];
    }

    $url = self::normalizeMeURL($url);
    $url = self::resolveMeURL($url);

    $authorizationEndpoint = self::discoverAuthorizationEndpoint($url);

    if(!$authorizationEndpoint) {
      return [false, [
        'error' => 'missing_authorization_endpoint',
        'error_description' => 'Could not find your authorization endpoint'
      ]];
    }

    if($scope) {
      $tokenEndpoint = self::discoverTokenEndpoint($url);

      if(!$tokenEndpoint) {
        return [false, [
          'error' => 'missing_token_endpoint',
          'error_description' => 'Could not find your token endpoint'
        ]];
      }
    }

    $state = self::generateStateParameter();

    $_SESSION['indieauth_url'] = $url;
    $_SESSION['indieauth_state'] = $state;
    $_SESSION['indieauth_authorization_endpoint'] = $authorizationEndpoint;
    if($scope)
      $_SESSION['indieauth_token_endpoint'] = $tokenEndpoint;

    $authorizationURL = self::buildAuthorizationURL($authorizationEndpoint, $url, self::$redirectURL, self::$clientID, $state, $scope);

    return [$authorizationURL, false];
  }

  public static function complete($params) {
    $requiredSessionKeys = ['indieauth_url', 'indieauth_state', 'indieauth_authorization_endpoint'];
    foreach($requiredSessionKeys as $key) {
      if(!isset($_SESSION[$key])) {
        return [false, [
          'error' => 'invalid_session',
          'error_description' => 'The session was missing data. Ensure that you are initializing the session before using this library'
        ]];
      }
    }

    if(isset($params['error'])) {
      return [false, [
        'error' => $params['error'],
        'error_description' => (isset($params['error_description']) ? $params['error_description'] : '')
      ]];
    }

    if(!isset($params['code'])) {
      return [false, [
        'error' => 'invalid_response',
        'error_description' => 'The response from the authorization server did not return an authorization code or error information'
      ]];
    }

    if(!isset($params['state'])) {
      return [false, [
        'error' => 'missing_state',
        'error_description' => 'The authorization server did not return the state parameter'
      ]];
    }

    if($params['state'] != $_SESSION['indieauth_state']) {
      return [false, [
        'error' => 'invalid_state',
        'error_description' => 'The authorization server returned an invalid state parameter'
      ]];
    }

    if(isset($_SESSION['indieauth_token_endpoint'])) {
      $verify = self::getAccessToken($_SESSION['indieauth_token_endpoint'], $params['code'], $_SESSION['indieauth_url'], self::$redirectURL, self::$clientID);
    } else {
      $verify = self::verifyIndieAuthCode($_SESSION['indieauth_authorization_endpoint'], $params['code'], null, self::$redirectURL, self::$clientID);
    }

    $expectedURL = $_SESSION['indieauth_url'];
    unset($_SESSION['indieauth_url']);
    unset($_SESSION['indieauth_state']);
    unset($_SESSION['indieauth_authorization_endpoint']);
    unset($_SESSION['indieauth_token_endpoint']);

    if(!isset($verify['me'])) {
      return [false, [
        'error' => 'indieauth_error',
        'error_description' => 'The authorization code was not able to be verified'
      ]];
    }

    // Check that the returned URL is on the same domain as the original URL
    if(parse_url($verify['me'], PHP_URL_HOST) != parse_url($expectedURL, PHP_URL_HOST)) {
      return [false, [
        'error' => 'invalid user',
        'error_description' => 'The domain for the user returned did not match the domain of the user initially signing in'
      ]];
    }

    $verify['me'] = self::normalizeMeURL($verify['me']);

    return [$verify, false];
  }


  public static function setUpHTTP() {
    // Unfortunately I've seen a bunch of websites return different content when the user agent is set to something like curl or other server-side libraries, so we have to pretend to be a browser to successfully get the real HTML
    if(!isset(self::$http)) {
      self::$http = new \p3k\HTTP();
      self::$http->set_user_agent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.57 Safari/537.36 indieauth-client/0.2.5');
      self::$http->_timeout = 10;
      // You can customize the user agent for your application by calling
      // IndieAuth\Client::$http->set_user_agent('Your User Agent String');
    }
  }

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
    self::setUpHTTP();

    if(array_key_exists($url, self::$_headers)) {
      return self::$_headers[$url];
    } else {
      $headers = self::$http->head($url);
      self::$_headers[$url] = $headers['header'];
      return self::$_headers[$url];
    }
  }

  private static function _fetchBody($url) {
    self::setUpHTTP();

    if(array_key_exists($url, self::$_body)) {
      return self::$_body[$url];
    } else {
      $response = self::$http->get($url);
      self::$_body[$url] = $response['body'];
      return self::$_body[$url];
    }
  }

  private static function _discoverEndpoint($url, $name) {
    if(!self::_urlIsValid($url))
      return null;

    // First check the HTTP headers for an authorization endpoint
    $headerString = self::_fetchHead($url);

    if($endpoint = self::_extractEndpointFromHeaders($headerString, $url, $name))
      return $endpoint;

    // If not found, check the body for a rel value
    $html = self::_fetchBody($url);

    return self::_extractEndpointFromHTML($html, $url, $name);
  }

  private static function _extractEndpointFromHeaders($headerString, $url, $name) {
    $headers = \IndieWeb\http_rels($headerString);

    if(isset($headers[$name][0])) {
      return \Mf2\resolveUrl($url, $headers[$name][0]);
    }

    return false;
  }

  private static function _extractEndpointFromHTML($html, $url, $name) {
    if(self::$_parsedHash != ($h=md5($html))) {
      $parser = new \Mf2\Parser($html);
      self::$_parsed = $parser->parse();
      self::$_parsedHash = $h;
    }

    if(isset(self::$_parsed['rels'][$name][0])) {
      return \Mf2\resolveUrl($url, self::$_parsed['rels'][$name][0]);
    }

    return false;
  }

  public static function resolveMeURL($url, $max=4) {
    // Follow redirects and return the identity URL at the end of the chain.
    // Permanent redirects affect the identity URL, temporary redirects do not.
    // A maximum of N redirects will be followed.
    self::setUpHTTP();

    $oldmax = self::$http->_max_redirects;
    self::$http->_max_redirects = 0;

    $i = 0;
    while($i < $max) {
      $result = self::$http->head($url);
      if($result['code'] == 200) {
        break;
      } elseif($result['code'] == 301) {
        // Follow the permanent redirect
        if(isset($result['headers']['Location']) && is_string($result['headers']['Location'])) {
          $url = $result['headers']['Location'];
        } else {
          $url = false; // something wrong with the Location header
        }
      } elseif($result['code'] == 302) {
        // Temporary redirect, so abort with the current URL
        break;
      } else {
        $url = false;
        break;
      }
      $i++;
    }

    self::$http->_max_redirects = $oldmax;
    return $url;
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
  //         or return false if not a valid IndieAuth URL (has a fragment)
  public static function normalizeMeURL($url) {
    $me = parse_url($url);

    if(array_key_exists('path', $me) && $me['path'] == '')
      return false;

    // parse_url returns just "path" for naked domains, so
    // move that into the "host" instead
    if(count($me) == 1 && array_key_exists('path', $me)) {
      if(preg_match('/([^\/]+)(\/.+)/', $me['path'], $match)) {
        $me['host'] = $match[1];
        $me['path'] = $match[2];
      } else {
        $me['host'] = $me['path'];
        unset($me['path']);
      }
    }

    if(!array_key_exists('scheme', $me))
      $me['scheme'] = 'http';

    if(!array_key_exists('path', $me))
      $me['path'] = '/';

    // Invalid scheme
    if(!in_array($me['scheme'], array('http','https')))
      return false;

    // fragment not allowed
    if(array_key_exists('fragment', $me))
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
    self::setUpHTTP();

    $response = self::$http->post($tokenEndpoint, http_build_query(array(
      'grant_type' => 'authorization_code',
      'me' => $me,
      'code' => $code,
      'redirect_uri' => $redirectURI,
      'client_id' => $clientID
    )), array(
      'Accept: application/json, application/x-www-form-urlencoded;q=0.8'
    ));

    $auth = json_decode($response['body'], true);
    if(!$auth) {
      // Parse as form-encoded for fallback support
      $auth = array();
      parse_str($response['body'], $auth);
    }

    if($debug) {
      return array(
        'auth' => $auth,
        'response' => $response['body'],
        'response_code' => $response['code']
      );
    } else {
      return $auth;
    }
  }

  // Note: the $me parameter is deprecated and you can just pass null instead
  public static function verifyIndieAuthCode($authorizationEndpoint, $code, $me, $redirectURI, $clientID, $debug=false) {
    self::setUpHTTP();

    $response = self::$http->post($authorizationEndpoint, http_build_query(array(
      'code' => $code,
      'redirect_uri' => $redirectURI,
      'client_id' => $clientID
    )), array(
      'Accept: application/json, application/x-www-form-urlencoded;q=0.8'
    ));

    $auth = json_decode($response['body'], true);
    if(!$auth) {
      // Parse as form-encoded for fallback support
      $auth = array();
      parse_str($response['body'], $auth);
    }

    if($debug) {
      return array(
        'auth' => $auth,
        'response' => $response['body'],
        'response_code' => $response['code']
      );
    } else {
      return $auth;
    }
  }

  public static function representativeHCard($url) {
    $html = self::_fetchBody($url);
    $parsed = \Mf2\parse($html, $url);
    return \Mf2\HCard\representative($parsed, $url);
  }

}
