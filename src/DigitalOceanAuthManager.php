<?php

namespace Drupal\social_auth_digitalocean;

use Drupal\social_auth\AuthManager\OAuth2Manager;
use Drupal\Core\Config\ConfigFactory;

/**
 * Contains all the logic for DigitalOcean login integration.
 */
class DigitalOceanAuthManager extends OAuth2Manager {

  /**
   * Constructor.
   *
   * @param \Drupal\Core\Config\ConfigFactory $configFactory
   *   Used for accessing configuration object factory.
   */
  public function __construct(ConfigFactory $configFactory) {
    parent::__construct($configFactory->get('social_auth_digitalocean.settings'));
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate() {
    $this->setAccessToken($this->client->getAccessToken('authorization_code',
      ['code' => $_GET['code']]));
  }

  /**
   * {@inheritdoc}
   */
  public function getUserInfo() {
    $this->user = $this->client->getResourceOwner($this->getAccessToken());
    return $this->user;
  }

  /**
   * {@inheritdoc}
   */
  public function getAuthorizationUrl() {
    $scopes = $this->getScopes();

    // Returns the URL where user will be redirected.
    return $this->client->getAuthorizationUrl([
      'scope' => $scopes,
    ]);
  }

  /**
   * {@inheritdoc}
   */
  public function requestEndPoint($path) {
    $url = 'https://api.digitalocean.com' . $path;

    $request = $this->client->getAuthenticatedRequest('GET', $url, $this->getAccessToken());

    $response = $this->client->getResponse($request);

    return $response->getBody()->getContents();
  }

  /**
   * {@inheritdoc}
   */
  public function getState() {
    return $this->client->getState();
  }

}
