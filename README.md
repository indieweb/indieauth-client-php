IndieAuth Client
================

This is a simple library to help with IndieAuth. There are two ways you may want to use it, either when developing an application that signs people in using IndieAuth, or when developing your own endpoint for issuing access tokens and you need to verify auth codes.

[![Build Status](https://travis-ci.org/indieweb/indieauth-client-php.png?branch=main)](http://travis-ci.org/indieweb/indieauth-client-php)


Quick Start
-----------

If you want to get started quickly, and if you're okay with letting the library store things in the PHP session itself, then you can follow the examples below. If you need more control or want to step into the details of the IndieAuth flow, see the [Detailed Usage for Clients](#detailed-usage-for-clients-detailed) below.

### Create a Login Form

You'll first need to create a login form to prompt the user to enter their website address. This might look something like the HTML below.

```html
<form action="/login.php" method="post">
  <input type="url" name="url">
  <input type="submit" value="Log In">
</form>
```

### Begin the Login Flow

In the `login.php` file, you'll need to initialize the session, and tell this library to discover the user's endpoints. If everything succeeds, the library will return a URL that you can use to redirect the user to begin the flow.

The example below will have some really basic error handling, which you'll probably want to replace with something nicer looking.

Example `login.php` file:

```php
<?php

if(!isset($_POST['url'])) {
  die('Missing URL');
}

// Start a session for the library to be able to save state between requests.
session_start();

// You'll need to set up two pieces of information before you can use the client,
// the client ID and and the redirect URL.

// The client ID should be the home page of your app.
IndieAuth\Client::$clientID = 'https://example.com/';

// The redirect URL is where the user will be returned to after they approve the request.
IndieAuth\Client::$redirectURL = 'https://example.com/redirect.php';

// Pass the user's URL and your requested scope to the client.
// If you are writing a Micropub client, you should include at least the "create" scope.
// If you are just trying to log the user in, you can omit the second parameter.

list($authorizationURL, $error) = IndieAuth\Client::begin($_POST['url'], 'create');
// or list($authorizationURL, $error) = IndieAuth\Client::begin($_POST['url']);

// Check whether the library was able to discover the necessary endpoints
if($error) {
  echo "<p>Error: ".$error['error']."</p>";
  echo "<p>".$error['error_description']."</p>";
} else {
  // Redirect the user to their authorization endpoint
  header('Location: '.$authorizationURL);
}

```

The following scopes have special meaning to the authorization server and will request the user's full profile info instead of just verifying their profile URL:

* `profile`
* `email`

Any other scopes requested are assumed to be scopes that will request an access token be returned and the library will request an access token from the token endpoint in the next step.


### Handling the Redirect

In your redirect file, you just need to pass all the query string parameters to the library and it will take care of things! It will use the authorization or token endpoint it found in the initial step, and will use the authorization code to verify the profile information or get an access token depending on whether you've requested any scopes.

The result will be the response from the authorization endpoint or token, which will contain the user's final `me` URL as well as the access token if you requested one or more scopes.

If there were any problems, the error information will be returned to you as well.

The library takes care of verifying the final returned profile URL has the same authorization endpoint as the entered URL.

Example `redirect.php` file:

```php
<?php
session_start();
IndieAuth\Client::$clientID = 'https://example.com/';
IndieAuth\Client::$redirectURL = 'https://example.com/redirect.php';

list($response, $error) = IndieAuth\Client::complete($_GET);

if($error) {
  echo "<p>Error: ".$error['error']."</p>";
  echo "<p>".$error['error_description']."</p>";
} else {
  // Login succeeded!
  // The library will return the user's profile URL in the property "me"
  // It will also return the full response from the authorization or token endpoint, as well as debug info
  echo "URL: ".$response['me']."<br>";
  if(isset($response['response']['access_token'])) {
    echo "Access Token: ".$response['response']['access_token']."<br>";
    echo "Scope: ".$response['response']['scope']."<br>";
  }

  // The full parsed response from the endpoint will be available as:
  // $response['response']

  // The raw response:
  // $response['raw_response']

  // The HTTP response code:
  // $response['response_code']

  // You'll probably want to save the user's URL in the session
  $_SESSION['user'] = $user['me'];
}

```


Detailed Usage for Clients
--------------------------

The first thing an IndieAuth client needs to do is to prompt the user to enter their web address. This is the basis of IndieAuth, where user identifiers are URLs. A typical IndieAuth sign-in form may look something like the following.

```
Your URL: [ example.com ]

       [ Sign In ]
```

This form will make a POST request to your app's server, at which point you can begin the IndieAuth discovery.

### Discovering the required endpoints

The user will need to define up to four endpoints for their URL before a client can perform authorization. Endpoints can be specified by either an HTTP `Link` header or by using `<link>` tags in the HTML head.

These discovery methods can be run all sequentially and the library will avoid making duplicate HTTP requests if it has already fetched the page once.


#### Authorization Endpoint

```html
<link rel="authorization_endpoint" href="https://example.com/auth">
```

```
Link: <https://example.com/auth>; rel="authorization_endpoint"
```

The authorization endpoint allows a website to specify the location to direct the user's browser to when performing the initial authorization request.

Since this can be a full URL, this allows a website to use an external auth server such as [indieauth.com](https://indieauth.com) as its authorization endpoint. This allows people to delegate the handling and verification of authorization and authentication to an external service to speed up development. Of course at any point, the authorization server can be changed, and API clients and users will not need any modifications.

The following function will fetch the user's home page and return the authorization endpoint, or `false` if none was found.

```php
// Normalize whatever the user entered to be a URL, e.g. "example.com" to "http://example.com/"
$url = IndieAuth\Client::normalizeMeURL($url);
$authorizationEndpoint = IndieAuth\Client::discoverAuthorizationEndpoint($url);
```

#### Token Endpoint

```html
<link rel="token_endpoint" href="https://example.com/token">
```

```
Link: <https://example.com/token>; rel="token_endpoint"
```

The token endpoint is where API clients will request access tokens. This will typically be a URL on the user's own website, although this can delegated to an external service as well.

The token endpoint is responsible for issuing an access token.

The following function will fetch the user's home page and return the token endpoint, or `false` if none was found.

```php
$url = IndieAuth\Client::normalizeMeURL($url);
$tokenEndpoint = IndieAuth\Client::discoverTokenEndpoint($url);
```

#### Micropub Endpoint

```html
<link rel="micropub" href="https://example.com/micropub">
```

```
Link: <https://example.com/micropub>; rel="micropub"
```

The [Micropub](https://indieweb.org/Micropub) endpoint defines where Micropub clients will make POST requests to create new posts on the user's website. When a Micropub client makes a request, the request will contain the previously-issued access token in the header, and the micropub endpoint will be able to validate the request given that access token.

The following function will fetch the user's home page and return the Micropub endpoint, or `false` if none was found.

```php
$url = IndieAuth\Client::normalizeMeURL($url);
$micropubEndpoint = IndieAuth\Client::discoverMicropubEndpoint($url);
```

The client may wish to discover all endpoints at the beginning, and cache the values in a session for later use.

#### Microsub Endpoint

```html
<link rel="microsub" href="https://example.com/microsub">
```

```
Link: <https://example.com/microsub>; rel="microsub"
```

The [Microsub](https://indieweb.comorg/Microsub) endpoint is for [readers](https://indieweb.org/reader). When a Micropub client makes a request, the request will contain the previously-issued access token in the header, and the endpoint will be able to validate the request given that access token.

The following function will fetch the user's home page and return the Microsub endpoint, or `false` if none was found.

```php
$url = IndieAuth\Client::normalizeMeURL($url);
$microsubEndpoint = IndieAuth\Client::discoverMicrosubEndpoint($url);
```

The client may wish to discover all endpoints at the beginning, and cache the values in a session for later use.


### Building the authorization URL

Once the client has discovered the authorization server, it will need to build the authorization URL and direct the user's browser there.

For web sites, the client should send a 301 redirect to the authorization URL, or can open a new browser window. Native apps must launch a native browser window to the autorization URL and handle the redirect back to the native app appropriately.

#### Authorization Endpoint Parameters
* `me` - the URL the user entered to begin the flow.
* `redirect_uri` - where the authorization server should redirect after authorization is complete.
* `client_id` - the full URL to a web page of the application. This is used by the authorization server to discover the app's name and icon, and to validate the redirect URI.
* `state` - the "state" parameter can be whatever the client wishes, and must also be sent to the token endpoint when the client exchanges the authorization code for an access token.
* `scope` - the "scope" value is a space-separated list of permissions the client is requesting.
* `code_challenge` - for [PKCE](https://oauth.net/2/pkce/) support, this is the hashed version of a secret the client generates when it starts.
* `code_challenge_method` - this library will always use S256 as the hash method.

The following function will build the authorization URL given all the required parameters. If the authorization endpoint contains a query string, this function handles merging the existing query string parameters with the new parameters.

The following scopes have special meaning to the authorization server and will request the user's full profile info instead of just verifying their profile URL:

* `profile`
* `email`

```php
$url = IndieAuth\Client::normalizeMeURL($url);

$scope = 'profile create'; // Request profile info as well as an access token with the "create" scope

// These are two random strings. The helper methods in the library will use an available random number generaton depending on the PHP version.
$_SESSION['state'] = IndieAuth\Client::generateStateParameter();
$_SESSION['code_verifier'] = IndieAuth\Client::generatePKCECodeVerifier();

// you'll need to verify these later
$_SESSION['user_entered_url'] = $url;
$_SESSION['authorization_endpoint'] = $authorizationEndpoint;

$authorizationURL = IndieAuth\Client::buildAuthorizationURL($authorizationEndpoint, [
  'me' => $url,
  'redirect_uri' => $redirect_uri,
  'client_id' => $client_id,
  'scope' => $scope,
  'state' => $_SESSION['state'],
  'code_verifier' => $_SESSION['code_verifier'],
]);
```

Note: Your code should include the plaintext random code verifier, the `IndieAuth\Client` library will deal with hashing it for you in the request.

### Getting authorization from the user

At this point, the authorization server interacts with the user, presenting them with a description of the request. This will look something like the following typical OAuth prompt:

```
An application, "Quill" is requesting access to your website, "aaronparecki.com"

This application would like to be able to
* **create** new entries on your website

[ Approve ]   [ Deny ]
```

If the user approves the request, the authorization server will redirect back to the redirect URL specified, with the following parameters added to the query string:

* `code` - the authorization code
* `state` - the state value provided in the request


### Exchanging the authorization code for profile info

If the client is not trying to get an access token, just trying to verify the user's URL, then it will need to exchange the authorization code for profile information at the authorization endpoint.

The following function will make a POST request to the authorization endpoint and parse the result.

```php
$response = IndieAuth\Client::exchangeAuthorizationCode($authorizationEndpoint, [
  'code' => $_GET['code'],
  'redirect_uri' => $redirect_uri,
  'client_id' => $client_id,
  'code_verifier' => $_SESSION['code_verifier'],
]);
```

The `$response` variable will include the response from the endpoint, such as the following:

```php
array(
  'me' => 'https://aaronparecki.com/',
  'response' => [
    'me' => 'https://aaronparecki.com/',
    'profile' => [
      'name' => 'Aaron Parecki',
      'url' => 'https://aaronparecki.com/',
      'photo' => 'https://aaronparecki.com/images/profile.jpg'
    ]
  ],
  'raw_response' => '{"me":"https://aaronparecki.com/","profile":{"name":"Aaron Parecki","url":"https://aaronparecki.com/","photo":"https://aaronparecki.com/images/profile.jpg"}}',
  'response_code' => 200
);
```



### Exchanging the authorization code for an access token

If the client requested any scopes beyond profile scopes and is expecting an access token, it needs to exchange the authorization code for an access token at the token endpoint.

To get an access token, the client makes a POST request to the token endpoint, passing in the authorization code as well as the following parameters:

* `code` - the authorization code obtained
* `me` - the user's URL
* `redirect_uri` - must match the redirect URI used in the request to obtain the authorization code
* `client_id` - must match the client ID used in the initial request
* `code_verifier` - if the client included a code challenge in the authorization request, then it must include the plaintext secret in the code exchange step here

The following function will make a POST request to the token endpoint and parse the result.

```php
$response = IndieAuth\Client::exchangeAuthorizationCode($tokenEndpoint, [
  'code' => $_GET['code'],
  'redirect_uri' => $redirect_uri,
  'client_id' => $client_id,
  'code_verifier' => $_SESSION['code_verifier'],
]);
```

The `$response` variable will include the response from the token endpoint, such as the following:

```php
array(
  'response' => [
    'me' => 'https://aaronparecki.com/',
    'access_token' => 'xxxxxxxxx',
    'scope' => 'create'
  ],
  'raw_response' => '{"me":"https://aaronparecki.com/","access_token":"xxxxxxxxx","scope":"create"}',
  'response_code' => 200
);
```


### Verifying the Authorization Server

If you are using the individual methods instead of the begin/complete wrapper, then you'll need to double check that the URL returned has the same authorization endpoint as the one you used to begin the flow.

```php
if($response['me'] != $_SESSION['user_entered_url']) {
  $authorizationEndpoint = IndieAuth\Client::discoverAuthorizationEndpoint($response['me']);
  if($authorizationEndpoint != $_SESSION['authorization_endpoint']) {
    echo "The authorization endpoint at the profile URL is not the same as the one used to begin the flow!";
    die();
  }
}
```



### Making API requests

At this point, you are done using the IndieAuth client library and can begin making API requests directly to the user's website and micropub endpoint.

To make an API request, include the access token in an HTTP "Authorization" header like the following:

```
Authorization: Bearer xxxxxxxx
```




License
-------

Copyright 2013-2020 by Aaron Parecki and contributors

Available under the MIT and Apache 2.0 licenses. See LICENSE.txt

