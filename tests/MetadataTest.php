<?php  

class MetadataTest extends IndieAuthTestCase {

  public function testGetMetadata() {
    $json = '{"issuer":"https://example.com/","authorization_endpoint":"https://example.com/authorization-endpoint","token_endpoint":"https://example.com/token-endpoint"}';

    IndieAuth\Client::setMetadata('https://example.com/', $json);
    $metadata = IndieAuth\Client::getMetadata();

    $this->assertInternalType('array', $metadata);
    $this->assertArrayHasKey('issuer', $metadata);
    $this->assertArrayHasKey('authorization_endpoint', $metadata);
    $this->assertArrayHasKey('token_endpoint', $metadata);
  }

  public function testDiscoverFromMetadata() {
    $json = '{"issuer":"https://example.com/","authorization_endpoint":"https://example.com/authorization-endpoint","token_endpoint":"https://example.com/token-endpoint"}';

    IndieAuth\Client::setMetadata('https://example.com/', $json);

    $result = $this->_invokeStaticMethod(
      IndieAuth\Client::class,
      '_discoverFromMetadata',
      ['issuer']
    );

    $this->assertEquals($result, 'https://example.com/');

    $result = $this->_invokeStaticMethod(
      IndieAuth\Client::class,
      '_discoverFromMetadata',
      ['authorization_endpoint']
    );

    $this->assertEquals($result, 'https://example.com/authorization-endpoint');

    $result = $this->_invokeStaticMethod(
      IndieAuth\Client::class,
      '_discoverFromMetadata',
      ['token_endpoint']
    );

    $this->assertEquals($result, 'https://example.com/token-endpoint');

    $result = $this->_invokeStaticMethod(
      IndieAuth\Client::class,
      '_discoverFromMetadata',
      ['revocation_endpoint']
    );

    $this->assertNull($result);
  }

  public function testIsIssuerValid() {
    # scheme must be https
    $result = $this->_invokeStaticMethod(
      IndieAuth\Client::class,
      '_isIssuerValid',
      ['http://example.com/', 'https://example.com/indieauth-metadata-endpoint']
    );

    $this->assertFalse($result);

    # no query string allowed
    $result = $this->_invokeStaticMethod(
      IndieAuth\Client::class,
      '_isIssuerValid',
      ['https://example.com/?foo=bar', 'https://example.com/indieauth-metadata-endpoint']
    );

    $this->assertFalse($result);

    # no fragment allowed
    $result = $this->_invokeStaticMethod(
      IndieAuth\Client::class,
      '_isIssuerValid',
      ['https://example.com/#issuer', 'https://example.com/indieauth-metadata-endpoint']
    );

    $this->assertFalse($result);

    # issuer must be prefix of metadata endpoint
    $result = $this->_invokeStaticMethod(
      IndieAuth\Client::class,
      '_isIssuerValid',
      ['https://example.com/foo', 'https://example.com/indieauth-metadata-endpoint']
    );

    $this->assertFalse($result);

    # valid issuer
    $result = $this->_invokeStaticMethod(
      IndieAuth\Client::class,
      '_isIssuerValid',
      ['https://example.com/', 'https://example.com/indieauth-metadata-endpoint']
    );

    $this->assertTrue($result);
  }

}
