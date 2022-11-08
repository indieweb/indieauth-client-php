<?php

namespace IndieAuth;

class ErrorResponse
{
  private $code;
  private $description;
  private $debug;

  public function __construct($code, $description, $debug = null)
  {
    $this->code = $code;
    $this->description = $description;
    $this->debug = $debug;
  }

  /**
   * @return array
   */
  public function getArray()
  {
    $response = [
      'error' => $this->code,
      'error_description' => $this->description,
    ];

    if ($this->debug) {
      $response['debug'] = $this->debug;
    }

    return [false, $response];
  }
}

