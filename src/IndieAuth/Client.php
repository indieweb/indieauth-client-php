<?php

namespace IndieAuth;

class Client {
  const VERSION = '1.1.6';

  private static $_headers = array();
  private static $_body = array();
  private static $_parsed = null;
  private static $_parsedHash = null;
  private static $_metadata_body = array();
  private static $_metadata = null;

  public static $http;

  public static $clientID;
  public static $redirectURL;
  public static $random_byte_count = 8;

  // Handles everything you need to start the authorization process.
  // Discovers the user's auth endpoints, generates and stores a state in the session.
  // Returns an authorization URL or an error array.
  // Note: the third parameter $authorizationEndpoint is a nonstandard parameter only used
  // when this client is used with services like indielogin.com
  public static function begin($url, $scope=false, $authorizationEndpoint=false) {
    if(!isset(self::$clientID) || !isset(self::$redirectURL)) {
      return self::_errorResponse('not_configured', 'Before you can begin, you need to configure the clientID and redirectURL of the IndieAuth client');
    }

    $errorCode = false;

    $url = self::normalizeMeURL($url);

    $_SESSION['indieauth_entered_url'] = $url;

    if(!$url) {
      return self::_errorResponse('invalid_url', 'The URL provided was invalid');
    }

    $metadataEndpoint = self::discoverMetadataEndpoint($url);
    if ($metadataEndpoint) {
      $response = self::discoverIssuer($metadataEndpoint);
      if ($response instanceof ErrorResponse) {
        return $response->getArray();
      }

      $_SESSION['indieauth_issuer'] = $response;
    }

    if(!$authorizationEndpoint) {
      $authorizationEndpoint = static::discoverAuthorizationEndpoint($url);
    }

    if(!$authorizationEndpoint) {
      return self::_errorResponse('missing_authorization_endpoint', 'Could not find your authorization endpoint');
    }

    $scopes = self::parseNonProfileScopes($scope);
    if(count($scopes)) {
      $tokenEndpoint = static::discoverTokenEndpoint($url);

      if(!$tokenEndpoint) {
        return self::_errorResponse('missing_token_endpoint', 'Could not find your token endpoint. The token endpoint is required when requesting non-profile scopes');
      }
    }

    $state = self::generateStateParameter();
    $codeVerifier = self::generatePKCECodeVerifier();

    $_SESSION['indieauth_state'] = $state;
    $_SESSION['indieauth_code_verifier'] = $codeVerifier;
    $_SESSION['indieauth_authorization_endpoint'] = $authorizationEndpoint;
    if(isset($tokenEndpoint))
      $_SESSION['indieauth_token_endpoint'] = $tokenEndpoint;

    $authorizationURL = self::buildAuthorizationURL($authorizationEndpoint, [
      'me' => $url,
      'redirect_uri' => self::$redirectURL,
      'client_id' => self::$clientID,
      'state' => $state,
      'code_verifier' => $codeVerifier,
      'scope' => $scope,
    ]);

    return [$authorizationURL, false];
  }

  public static function complete($params) {
    $requiredSessionKeys = ['indieauth_entered_url', 'indieauth_state', 'indieauth_authorization_endpoint'];
    foreach($requiredSessionKeys as $key) {
      if(!isset($_SESSION[$key])) {
        return self::_errorResponse('invalid_session',
          'The session was missing data. Ensure that you are initializing the session before using this library');
      }
    }

    if(isset($params['error'])) {
      return self::_errorResponse($params['error'], isset($params['error_description']) ? $params['error_description'] : '');
    }

    if(!isset($params['code'])) {
      return self::_errorResponse('invalid_response',
        'The response from the authorization server did not return an authorization code or error information');
    }

    $response = self::validateStateMatch($params, $_SESSION['indieauth_state']);
    if ($response instanceof ErrorResponse) {
      return $response->getArray();
    }

    if (isset($_SESSION['indieauth_issuer'])) {
      $response = self::validateIssuerMatch($params, $_SESSION['indieauth_issuer']);
      if ($response instanceof ErrorResponse) {
        return $response->getArray();
      }
    }

    if(isset($_SESSION['indieauth_token_endpoint'])) {
      $data = self::exchangeAuthorizationCode($_SESSION['indieauth_token_endpoint'], [
        'code' => $params['code'],
        'redirect_uri' => self::$redirectURL,
        'client_id' => self::$clientID,
        'code_verifier' => $_SESSION['indieauth_code_verifier'],
      ]);
    } else {
      $data = self::exchangeAuthorizationCode($_SESSION['indieauth_authorization_endpoint'], [
        'code' => $params['code'],
        'redirect_uri' => self::$redirectURL,
        'client_id' => self::$clientID,
        'code_verifier' => $_SESSION['indieauth_code_verifier'],
      ]);
    }

    if(!isset($data['response']['me'])) {
      $error = 'indieauth_error';
      if(!empty($data['response_details']['error']))
        $error = $data['response_details']['error'];
      elseif(!empty($data['response']['error']))
        $error = $data['response']['error'];

      $error_description = 'The authorization server did not return a valid response';
      if(!empty($data['response_details']['error_description']))
        $error_description = $data['response_details']['error_description'];
      elseif(!empty($data['response']['error_description']))
        $error_description = $data['response']['error_description'];

      return self::_errorResponse($error, $error_description, $data);
    }

    // If the returned "me" is not the same as the entered "me", check that the authorization endpoint linked to
    // by the returned URL is the same as the one used
    if($_SESSION['indieauth_entered_url'] != $data['response']['me']) {
      // Discover and populate metadata if the returned "me" has a metadata endpoint
      $metadataEndpoint = self::discoverMetadataEndpoint($data['response']['me']);

      // Go find the authorization endpoint that the returned "me" URL declares
      $authorizationEndpoint = static::discoverAuthorizationEndpoint($data['response']['me']);

      if($authorizationEndpoint != $_SESSION['indieauth_authorization_endpoint']) {
        return self::_errorResponse('invalid_authorization_endpoint',
          'The authorization server of the returned profile URL did not match the initial authorization server', $data);
      }
    }

    $data['me'] = self::normalizeMeURL($data['response']['me']);

    self::_clearSessionData();

    return [$data, false];
  }

  /**
   * Wrapper to create an ErrorResponse and return the array
   * @return array
   */
  private static function _errorResponse($error_code, $description, $debug = null) {
    self::_clearSessionData();
    $error = new ErrorResponse($error_code, $description, $debug);
    return $error->getArray();
  }

  private static function _clearSessionData() {
    unset($_SESSION['indieauth_entered_url']);
    unset($_SESSION['indieauth_state']);
    unset($_SESSION['indieauth_code_verifier']);
    unset($_SESSION['indieauth_authorization_endpoint']);
    unset($_SESSION['indieauth_token_endpoint']);
    unset($_SESSION['indieauth_issuer']);
  }

  public static function setUpHTTP() {
    // Unfortunately I've seen a bunch of websites return different content when the user agent is set to something like curl or other server-side libraries, so we have to pretend to be a browser to successfully get the real HTML
    if(!isset(self::$http)) {
      self::$http = new \p3k\HTTP();
      self::$http->set_user_agent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36 indieauth-client/' . self::VERSION);
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

  /**
   * @see https://indieauth.spec.indieweb.org/#indieauth-server-metadata
   */
  private static function _isIssuerValid($issuer, $metadata_endpoint) {
    $issuer = self::normalizeMeURL($issuer);
    if (!$issuer) {
      return false;
    }

    $parts = parse_url($issuer);

    if (!array_key_exists('scheme', $parts) || $parts['scheme'] != 'https') {
      return false;
    }

    if (array_key_exists('query', $parts) || array_key_exists('fragment', $parts)) {
      return false;
    }

    $metadata_endpoint = self::normalizeMeURL($metadata_endpoint);

    if (strpos($metadata_endpoint, $issuer) !== 0) {
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

  private static function _fetchMetadata($url) {
    self::setUpHTTP();

    if(array_key_exists($url, self::$_metadata_body)) {
      return self::$_metadata_body[$url];
    } else {
      $response = self::$http->get($url);
      self::setMetadata($url, $response['body']);
      return self::$_metadata_body[$url];
    }
  }

  private static function resetMetadata() {
    self::$_metadata_body = array();
    self::$_metadata = null;
  }

  /**
   * Set metadata body
   * $body is expected to be JSON and will attempt
   * to decode to array in self::$_metadata
   */
  public static function setMetadata($url, $body) {
    self::resetMetadata();

    self::$_metadata_body[$url] = $body;
    $metadata_array = json_decode($body, true);
    if (!is_null($metadata_array)) {
      self::$_metadata = $metadata_array;
    }
  }

  public static function getMetadata() {
    return self::$_metadata;
  }

  private static function _discoverEndpoint($url, $name) {
    if(!self::_urlIsValid($url)) {
      return null;
    }

    // First check the parsed metadata for the endpoint
    if ($endpoint = self::_discoverFromMetadata($name)) {
      return $endpoint;
    }

    // If not found, check the HTTP headers for the endpoint
    $headerString = self::_fetchHead($url);

    if($endpoint = self::_extractEndpointFromHeaders($headerString, $url, $name)) {
      return $endpoint;
    }

    // If not found, check the body for a rel value
    $html = self::_fetchBody($url);

    return self::_extractEndpointFromHTML($html, $url, $name);
  }

  private static function _discoverFromMetadata($name) {
    if (!self::$_metadata) {
      return null;
    }

    if (array_key_exists($name, self::$_metadata)) {
      return self::$_metadata[$name];
    }

    return null;
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
      $parser->enableAlternates = true;
      self::$_parsed = $parser->parse();
      self::$_parsedHash = $h;
    }

    if(isset(self::$_parsed['rels'][$name][0])) {
      return \Mf2\resolveUrl($url, self::$_parsed['rels'][$name][0]);
    }

    return false;
  }

  public static function discoverMetadataEndpoint($url) {
    if ($endpoint = self::_discoverEndpoint($url, 'indieauth-metadata')) {
      self::_fetchMetadata($endpoint);
    }

    return $endpoint;
  }

  /**
   * @param string $metadataEndpoint
   * @return IndieAuth\ErrorResponse if error, string of `issuer` if valid
   */
  public static function discoverIssuer($metadataEndpoint) {
    $issuer = self::_discoverFromMetadata('issuer');
    if (!$issuer) {
      return new ErrorResponse('invalid_issuer', 'No issuer found in metadata endpoint');
    }

    if (!(self::_isIssuerValid($issuer, $metadataEndpoint))) {
      return new ErrorResponse('invalid_issuer', 'Issuer in metadata endpoint is not valid');
    }

    return $issuer;
  }

  public static function discoverAuthorizationEndpoint($url) {
    return self::_discoverEndpoint($url, 'authorization_endpoint');
  }

  public static function discoverTokenEndpoint($url) {
    return self::_discoverEndpoint($url, 'token_endpoint');
  }

  public static function discoverRevocationEndpoint($url) {
    return self::_discoverEndpoint($url, 'revocation_endpoint');
  }

  public static function discoverIntrospectionEndpoint($url) {
    return self::_discoverEndpoint($url, 'introspection_endpoint');
  }

  public static function discoverUserinfoEndpoint($url) {
    return self::_discoverEndpoint($url, 'userinfo_endpoint');
  }

  public static function discoverMicropubEndpoint($url) {
    return self::_discoverEndpoint($url, 'micropub');
  }

  public static function discoverMicrosubEndpoint($url) {
    return self::_discoverEndpoint($url, 'microsub');
  }

  // Build the authorization URL for the given url and endpoint
  public static function buildAuthorizationURL($authorizationEndpoint, $params) {
    $required = ['me', 'redirect_uri', 'client_id', 'state'];
    foreach($required as $r) {
      if(!isset($params[$r])) {
        throw new \Exception('Missing parameter to buildAuthorizationURL: '.$r);
      }
    }

    $url = parse_url($authorizationEndpoint);

    $request = array();
    if(array_key_exists('query', $url)) {
      parse_str($url['query'], $request);
    }

    $request['response_type'] = 'code';
    $request['me'] = $params['me'];
    $request['redirect_uri'] = $params['redirect_uri'];
    $request['client_id'] = $params['client_id'];
    $request['state'] = $params['state'];
    if(!empty($params['scope'])) {
      $request['scope'] = $params['scope'];
    }
    if(isset($params['code_verifier'])) {
      $request['code_challenge'] = self::generatePKCECodeChallenge($params['code_verifier']);
      $request['code_challenge_method'] = 'S256';
    }

    $url['query'] = http_build_query($request);

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
    $scheme   = isset($parsed_url['scheme']) ? strtolower($parsed_url['scheme']) . '://' : '';
    $host     = isset($parsed_url['host']) ? strtolower($parsed_url['host']) : '';
    $port     = isset($parsed_url['port']) ? ':' . $parsed_url['port'] : '';
    $user     = isset($parsed_url['user']) ? $parsed_url['user'] : '';
    $pass     = isset($parsed_url['pass']) ? ':' . $parsed_url['pass']  : '';
    $pass     = ($user || $pass) ? "$pass@" : '';
    $path     = isset($parsed_url['path']) ? $parsed_url['path'] : '';
    $query    = isset($parsed_url['query']) ? '?' . $parsed_url['query'] : '';
    $fragment = isset($parsed_url['fragment']) ? '#' . $parsed_url['fragment'] : '';
    return "$scheme$user$pass$host$port$path$query$fragment";
  }

  public static function parseNonProfileScopes($scope) {
    $scopes = explode(' ', $scope);
    return array_filter(array_diff($scopes, ['profile','email']));
  }

  /**
   * @param array $params
   * @param string $expected_state
   * @return IndieAuth\ErrorResponse if error, void (null) if valid
   */
  public static function validateStateMatch($params, $expected_state = '') {
    if (!isset($params['state'])) {
      return new ErrorResponse('missing_state', 'The authorization server did not return the state parameter');
    }

    if ($params['state'] !== $expected_state) {
      return new ErrorResponse('invalid_state', 'The authorization server returned an invalid state parameter');
    }
  }

  /**
   * @param array $params
   * @param string $expected_issuer
   * @return IndieAuth\ErrorResponse if error, void (null) if valid
   */
  public static function validateIssuerMatch($params, $expected_issuer = '') {
    if (!$expected_issuer) {
      return;
    }

    if (!isset($params['iss'])) {
      return new ErrorResponse('missing_iss', 'The authorization server did not return the iss parameter');
    }

    if ($params['iss'] !== $expected_issuer) {
      return new ErrorResponse('invalid_iss', 'The authorization server returned an invalid iss parameter');
    }
  }

  public static function exchangeAuthorizationCode($endpoint, $params) {
    $required = ['code', 'redirect_uri', 'client_id'];
    foreach($required as $r) {
      if(!isset($params[$r])) {
        throw new \Exception('Missing parameter to exchangeAuthorizationCode: '.$r);
      }
    }

    self::setUpHTTP();

    $request = [
      'grant_type' => 'authorization_code',
      'code' => $params['code'],
      'redirect_uri' => $params['redirect_uri'],
      'client_id' => $params['client_id'],
    ];
    if(isset($params['code_verifier'])) {
      $request['code_verifier'] = $params['code_verifier'];
    }

    $response = self::$http->post($endpoint, http_build_query($request), [
      'Accept: application/json, application/x-www-form-urlencoded;q=0.8'
    ]);

    $data = json_decode($response['body'], true);
    if(!$data) {
      // Parse as form-encoded for legacy server support
      $data = array();
      parse_str($response['body'], $data);
    }

    return [
      'response' => $data,
      'raw_response' => $response['body'],
      'response_code' => $response['code'],
      'response_details' => $response,
    ];
  }

  public static function representativeHCard($url) {
    $html = self::_fetchBody($url);
    $parsed = \Mf2\parse($html, $url);
    return \Mf2\HCard\representative($parsed, $url);
  }

  // Support legacy PHP random string generation methods
  private static function generateRandomString($numBytes) {
    if(function_exists('random_bytes')) {
      $bytes = random_bytes($numBytes);
    } elseif(function_exists('openssl_random_pseudo_bytes')){
      $bytes = openssl_random_pseudo_bytes($numBytes);
    } else {
      $bytes = '';
      for($i=0, $bytes=''; $i < $numBytes; $i++) {
        $bytes .= chr(mt_rand(0, 255));
      }
    }
    return bin2hex($bytes);
  }

  // Optional helper method to generate a state parameter. You can just as easily do this yourself some other way.
  public static function generateStateParameter() {
    return self::generateRandomString(self:: $random_byte_count);
  }

  /** PKCE Helpers **/

  public static function generatePKCECodeVerifier() {
    return self::generateRandomString(32);
  }

  private static function generatePKCECodeChallenge($plaintext) {
    return self::base64_urlencode(hash('sha256', $plaintext, true));
  }

  private static function base64_urlencode($string) {
    return rtrim(strtr(base64_encode($string), '+/', '-_'), '=');
  }

}

