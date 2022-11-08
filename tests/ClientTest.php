<?php  
/**
 * General IndieAuth Client tests
 */

use IndieAuth\Client;
use IndieAuth\ErrorResponse;

class ClientTest extends IndieAuthTestCase
{
  public function setUp(): void
  {
    if (!isset($_SESSION)) {
      $_SESSION = [];
    }
  }

  public function testErrorResponse()
  {
    $object = new ErrorResponse('missing_state', 'The state is missing', 'debug information');
    $result = $object->getArray();

    $this->assertIsArray($result);
    $this->assertCount(2, $result);

    if (isset($result[1])) {
      $error = $result[1];
      $this->assertIsArray($error);
      $this->assertCount(3, $error);

      $this->assertArrayHasKey('error', $error);
      $this->assertArrayHasKey('error_description', $error);
      $this->assertArrayHasKey('debug', $error);

      $this->assertEquals('missing_state', $error['error']);
      $this->assertEquals('The state is missing', $error['error_description']);
      $this->assertEquals('debug information', $error['debug']);
    }
  }

  public function testValidateState()
  {
    $expected_state = 'example_state';
    $params = ['state' => $expected_state];
    $response = Client::validateStateMatch($params, $expected_state);
    $this->assertNull($response);
  }

  public function testValidateStateCase()
  {
    $params = ['state' => 'example_state'];
    $response = Client::validateStateMatch($params, 'Example_State');
    $this->assertInstanceOf(ErrorResponse::class, $response);
  }

  public function testValidateStateMissing()
  {
    $params = [];
    $response = Client::validateStateMatch($params, 'state');
    $this->assertInstanceOf(ErrorResponse::class, $response);
  }

  public function testValidateStateMismatch()
  {
    $params = ['state' => 'example_state'];
    $response = Client::validateStateMatch($params, 'unexpected_state');
    $this->assertInstanceOf(ErrorResponse::class, $response);
  }

  public function testValidateIssuer()
  {
    $expected_issuer = 'https://issuer.example.com/';
    $params = ['iss' => $expected_issuer];
    $response = Client::validateIssuerMatch($params, $expected_issuer);
    $this->assertNull($response);
  }

  public function testValidateIssuerMissing()
  {
    $expected_issuer = 'https://issuer.example.com/';
    $params = [];
    $response = Client::validateIssuerMatch($params, $expected_issuer);
    $this->assertInstanceOf(ErrorResponse::class, $response);
  }

  public function testValidateIssuerMismatch()
  {
    $params = ['iss' => 'https://issuer.example.com/'];
    $response = Client::validateIssuerMatch($params, 'https://example.org/');
    $this->assertInstanceOf(ErrorResponse::class, $response);
  }

}

