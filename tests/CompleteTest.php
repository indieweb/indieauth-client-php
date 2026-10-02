<?php
/**
 * The whole flow, begin() to complete(), against fake servers.
 */

require_once __DIR__ . '/FakeTransport.php';

use IndieAuth\Client;

class CompleteTest extends IndieAuthTestCase
{
  private $http;

  public function setUp(): void
  {
    $_SESSION = [];
    $client = new \ReflectionClass(Client::class);
    foreach ($client->getProperties(\ReflectionProperty::IS_STATIC) as $property) {
      if (strpos($property->getName(), '_') === 0) {
        $property->setAccessible(true);
        $property->setValue(null, $property->getDefaultValue());
      }
    }
    $this->http = new FakeTransport();
    Client::$http = new \p3k\HTTP(null, $this->http);
    Client::$clientID = 'https://client.example/';
    Client::$redirectURL = 'https://client.example/callback';

    // Alice's site uses the authorization server at auth.example.
    $this->http->respond('GET', 'https://alice.example/', 200, '<link rel="indieauth-metadata" href="https://auth.example/metadata">');
    $this->http->json('GET', 'https://auth.example/metadata', [
      'issuer' => 'https://auth.example/',
      'authorization_endpoint' => 'https://auth.example/authorize',
      'token_endpoint' => 'https://auth.example/token',
    ]);
  }

  /**
   * Mallory's site copies Alice's authorization endpoint into its own
   * metadata but redeems codes at its own token endpoint, which answers
   * with Alice's profile URL.
   */
  private function mallory()
  {
    $this->http->respond('GET', 'https://mallory.example/', 200, '<link rel="indieauth-metadata" href="https://mallory.example/metadata">');
    $this->http->json('GET', 'https://mallory.example/metadata', [
      'issuer' => 'https://mallory.example/',
      'authorization_endpoint' => 'https://auth.example/authorize',
      'token_endpoint' => 'https://mallory.example/token',
    ]);
    $this->http->json('POST', 'https://mallory.example/token', ['me' => 'https://alice.example/', 'access_token' => 'x']);
  }

  private function signInAs($me, $iss)
  {
    list($url, $error) = Client::begin($me, 'create');
    $this->assertFalse($error);
    return Client::complete(['code' => 'c', 'state' => $_SESSION['indieauth_state'], 'iss' => $iss]);
  }

  public function testSignIn()
  {
    $this->http->json('POST', 'https://auth.example/token', ['me' => 'https://alice.example/', 'access_token' => 'tok']);

    list($data, $error) = $this->signInAs('https://alice.example/', 'https://auth.example/');

    $this->assertFalse($error);
    $this->assertEquals('https://alice.example/', $data['me']);
  }

  public function testReturnedProfileOnTheSameServerIsAccepted()
  {
    $this->http->respond('GET', 'https://alice.example/about', 200, '<link rel="indieauth-metadata" href="https://auth.example/metadata">');
    $this->http->json('POST', 'https://auth.example/token', ['me' => 'https://alice.example/about', 'access_token' => 'tok']);

    list($data, $error) = $this->signInAs('https://alice.example/', 'https://auth.example/');

    $this->assertFalse($error);
    $this->assertEquals('https://alice.example/about', $data['me']);
  }

  public function testReturnedProfileFromAnotherTokenEndpointIsRefused()
  {
    $this->mallory();

    list($data, $error) = $this->signInAs('https://mallory.example/', 'https://mallory.example/');

    $this->assertFalse($data);
    $this->assertEquals('invalid_authorization_endpoint', $error['error']);
  }

  public function testReturnedProfileWithOnlyRelLinksIsRefused()
  {
    // Alice's site has no metadata: Mallory's must not stand in for it.
    $this->http->respond('GET', 'https://alice.example/', 200, '<link rel="authorization_endpoint" href="https://auth.example/authorize"><link rel="token_endpoint" href="https://auth.example/token">');
    $this->mallory();

    list($data, $error) = $this->signInAs('https://mallory.example/', 'https://mallory.example/');

    $this->assertFalse($data);
    $this->assertEquals('invalid_authorization_endpoint', $error['error']);
  }

  public function testMetadataIsNotReusedForAnotherSite()
  {
    Client::discoverMetadataEndpoint('https://alice.example/');
    $this->http->respond('GET', 'https://bob.example/', 200, '<link rel="token_endpoint" href="https://bob.example/token">');

    $this->assertEquals('https://bob.example/token', Client::discoverTokenEndpoint('https://bob.example/'));
    Client::discoverMetadataEndpoint('https://bob.example/');
    $this->assertNull(Client::getMetadata());
    $this->assertFalse(Client::discoverAuthorizationEndpoint('https://bob.example/'));
  }

  public function testEndpointsMustBeHttp()
  {
    $this->http->respond('GET', 'https://carol.example/', 200, '<link rel="authorization_endpoint" href="https://carol.example/auth"><link rel="token_endpoint" href="gopher://127.0.0.1:6379/_x"><link rel="micropub" href="file:///etc/passwd">');

    $this->assertEquals('https://carol.example/auth', Client::discoverAuthorizationEndpoint('https://carol.example/'));
    $this->assertFalse(Client::discoverTokenEndpoint('https://carol.example/'));
    $this->assertFalse(Client::discoverMicropubEndpoint('https://carol.example/'));
  }

  public function testErrorIsOnlyReportedWithTheRightState()
  {
    Client::begin('https://alice.example/', 'create');
    $state = $_SESSION['indieauth_state'];

    list($data, $error) = Client::complete(['error' => 'access_denied', 'error_description' => 'Call 555-0100']);
    $this->assertEquals('missing_state', $error['error']);

    Client::begin('https://alice.example/', 'create');
    list($data, $error) = Client::complete(['error' => 'access_denied', 'error_description' => 'No thanks', 'state' => $_SESSION['indieauth_state']]);
    $this->assertEquals('access_denied', $error['error']);
    $this->assertEquals('No thanks', $error['error_description']);
  }
}
