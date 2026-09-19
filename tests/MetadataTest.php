<?php  

use IndieAuth\Client;
use IndieAuth\ErrorResponse;

class MetadataTest extends IndieAuthTestCase {

  private $default_metadata = '{"issuer":"https://example.com/","authorization_endpoint":"https://example.com/authorization-endpoint","token_endpoint":"https://example.com/token-endpoint","revocation_endpoint":"https://example.com/revocation-endpoint","introspection_endpoint":"https://example.com/introspection-endpoint","userinfo_endpoint":"https://example.com/userinfo-endpoint"}';

  public function testSetAndGetMetadata() {
    Client::setMetadata('https://example.com/', $this->default_metadata);
    $metadata = Client::getMetadata();

    $this->assertIsArray($metadata);
    $this->assertArrayHasKey('issuer', $metadata);
    $this->assertArrayHasKey('authorization_endpoint', $metadata);
    $this->assertArrayHasKey('token_endpoint', $metadata);
    $this->assertArrayHasKey('revocation_endpoint', $metadata);
    $this->assertArrayHasKey('introspection_endpoint', $metadata);
  }

  public function testSetMetadataInvalid() {
    # malfored JSON
    Client::setMetadata('https://example.com/', '{"issuer":"https://example.com/');
    $metadata = Client::getMetadata();
    $this->assertNull($metadata);

    # other content like HTML
    Client::setMetadata('https://example.com/', '<p> invalid metdata </p>');
    $metadata = Client::getMetadata();
    $this->assertNull($metadata);
  }

  public function testDiscoverFromMetadata() {
    Client::setMetadata('https://example.com/', $this->default_metadata);

    $result = $this->_invokeStaticMethod(
      Client::class,
      '_discoverFromMetadata',
      ['issuer']
    );

    $this->assertEquals('https://example.com/', $result);

    $result = $this->_invokeStaticMethod(
      Client::class,
      '_discoverFromMetadata',
      ['authorization_endpoint']
    );

    $this->assertEquals($result, 'https://example.com/authorization-endpoint');

    $result = $this->_invokeStaticMethod(
      Client::class,
      '_discoverFromMetadata',
      ['token_endpoint']
    );

    $this->assertEquals('https://example.com/token-endpoint', $result);

    $result = $this->_invokeStaticMethod(
      Client::class,
      '_discoverFromMetadata',
      ['revocation_endpoint']
    );

    $this->assertEquals('https://example.com/revocation-endpoint', $result);

    $result = $this->_invokeStaticMethod(
      Client::class,
      '_discoverFromMetadata',
      ['introspection_endpoint']
    );

    $this->assertEquals('https://example.com/introspection-endpoint', $result);

    $result = $this->_invokeStaticMethod(
      Client::class,
      '_discoverFromMetadata',
      ['userinfo_endpoint']
    );

    $this->assertEquals('https://example.com/userinfo-endpoint', $result);
  }

  public function testIsIssuerValid() {
    # scheme must be https
    $result = $this->_invokeStaticMethod(
      Client::class,
      '_isIssuerValid',
      ['http://example.com/', 'https://example.com/indieauth-metadata-endpoint']
    );

    $this->assertFalse($result);

    # no query string allowed
    $result = $this->_invokeStaticMethod(
      Client::class,
      '_isIssuerValid',
      ['https://example.com/?foo=bar', 'https://example.com/indieauth-metadata-endpoint']
    );

    $this->assertFalse($result);

    # no fragment allowed
    $result = $this->_invokeStaticMethod(
      Client::class,
      '_isIssuerValid',
      ['https://example.com/#issuer', 'https://example.com/indieauth-metadata-endpoint']
    );

    $this->assertFalse($result);

    # issuer must be prefix of metadata endpoint
    $result = $this->_invokeStaticMethod(
      Client::class,
      '_isIssuerValid',
      ['https://example.com/foo', 'https://example.com/indieauth-metadata-endpoint']
    );

    $this->assertFalse($result);

    # valid issuer
    $result = $this->_invokeStaticMethod(
      Client::class,
      '_isIssuerValid',
      ['https://example.com/', 'https://example.com/indieauth-metadata-endpoint']
    );

    $this->assertTrue($result);

    # RFC 8414: the well-known path is inserted between the host and the issuer's path
    $result = $this->_invokeStaticMethod(
      Client::class,
      '_isIssuerValid',
      ['https://example.com/s/abc/', 'https://example.com/.well-known/oauth-authorization-server/s/abc']
    );

    $this->assertTrue($result);

    # ... also with the OpenID Connect document name
    $result = $this->_invokeStaticMethod(
      Client::class,
      '_isIssuerValid',
      ['https://example.com/s/abc/', 'https://example.com/.well-known/openid-configuration/s/abc']
    );

    $this->assertTrue($result);

    # ... and for an issuer without a path (also a prefix match)
    $result = $this->_invokeStaticMethod(
      Client::class,
      '_isIssuerValid',
      ['https://example.com/', 'https://example.com/.well-known/oauth-authorization-server']
    );

    $this->assertTrue($result);

    # the well-known location for a different path is not this issuer's
    $result = $this->_invokeStaticMethod(
      Client::class,
      '_isIssuerValid',
      ['https://example.com/s/abc/', 'https://example.com/.well-known/oauth-authorization-server/s/xyz']
    );

    $this->assertFalse($result);

    # nor is the well-known location on another host
    $result = $this->_invokeStaticMethod(
      Client::class,
      '_isIssuerValid',
      ['https://example.com/s/abc/', 'https://example.org/.well-known/oauth-authorization-server/s/abc']
    );

    $this->assertFalse($result);

    # http is still refused, well-known or not
    $result = $this->_invokeStaticMethod(
      Client::class,
      '_isIssuerValid',
      ['http://example.com/s/abc/', 'http://example.com/.well-known/oauth-authorization-server/s/abc']
    );

    $this->assertFalse($result);
  }

  public function testWellKnownMetadataURLs() {
    $this->assertEquals([
      'https://example.com/.well-known/oauth-authorization-server/s/abc',
      'https://example.com/.well-known/openid-configuration/s/abc',
    ], Client::wellKnownMetadataURLs('https://example.com/s/abc/'));

    $this->assertEquals([
      'https://example.com:8443/.well-known/oauth-authorization-server',
      'https://example.com:8443/.well-known/openid-configuration',
    ], Client::wellKnownMetadataURLs('https://example.com:8443/'));

    $this->assertEquals([], Client::wellKnownMetadataURLs('not a url'));
  }

  public function testDiscoverIssuer()
  {
    Client::setMetadata('https://example.com/', $this->default_metadata);

    $result = $this->_invokeStaticMethod(
      Client::class,
      'discoverIssuer',
      ['https://example.com/indieauth-metadata-endpoint']
    );

    $this->assertEquals('https://example.com/', $result);
  }

  /**
   * `issuer` must be provided in indieauth-metadata
   */
  public function testDiscoverIssuerMissing()
  {
    Client::setMetadata('https://example.com/', '{"authorization_endpoint":"https://example.com/authorization-endpoint"}');
    $metadata_endpoint = 'https://example.com/indieauth-metadata-endpoint';

    $result = $this->_invokeStaticMethod(
      Client::class,
      'discoverIssuer',
      [$metadata_endpoint]
    );
    $this->assertInstanceOf(ErrorResponse::class, $result);
  }

  /**
   * `issuer` must be a prefix of the metadata endpoint
   */
  public function testDiscoverIssuerNotAPrefix()
  {
    Client::setMetadata('https://example.org/', $this->default_metadata);
    $metadata_endpoint = 'https://example.org/indieauth-metadata-endpoint';

    $result = $this->_invokeStaticMethod(
      Client::class,
      'discoverIssuer',
      [$metadata_endpoint]
    );
    $this->assertInstanceOf(ErrorResponse::class, $result);
  }

  /**
   * `issuer` may also name the RFC 8414 well-known location the metadata was fetched from
   */
  public function testDiscoverIssuerAtWellKnownLocation()
  {
    $metadata_endpoint = 'https://example.com/.well-known/oauth-authorization-server/s/abc';
    Client::setMetadata($metadata_endpoint, '{"issuer":"https://example.com/s/abc/","authorization_endpoint":"https://example.com/s/abc/auth","token_endpoint":"https://example.com/token"}');

    $result = $this->_invokeStaticMethod(
      Client::class,
      'discoverIssuer',
      [$metadata_endpoint]
    );
    $this->assertEquals('https://example.com/s/abc/', $result);
  }

  public function testDiscoverRevocationEndpoint() {
    Client::setMetadata('https://example.com/', $this->default_metadata);

    $result = $this->_invokeStaticMethod(
      Client::class,
      'discoverRevocationEndpoint',
      ['https://example.com/']
    );

    $this->assertEquals('https://example.com/revocation-endpoint', $result);
  }

  public function testDiscoverIntrospectionEndpoint() {
    Client::setMetadata('https://example.com/', $this->default_metadata);

    $result = $this->_invokeStaticMethod(
      Client::class,
      'discoverIntrospectionEndpoint',
      ['https://example.com/']
    );

    $this->assertEquals('https://example.com/introspection-endpoint', $result);
  }

  public function testDiscoverUserinfoEndpoint() {
    Client::setMetadata('https://example.com/', $this->default_metadata);

    $result = $this->_invokeStaticMethod(
      Client::class,
      'discoverUserinfoEndpoint',
      ['https://example.com/']
    );

    $this->assertEquals('https://example.com/userinfo-endpoint', $result);
  }

}
