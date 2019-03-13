<?php

namespace Drupal\social_auth_digitalocean\Plugin\Network;

use ChrisHemmings\OAuth2\Client\Provider\DigitalOcean;
use Drupal\Core\Url;
use Drupal\social_api\SocialApiException;
use Drupal\social_auth\Plugin\Network\NetworkBase;
use Drupal\social_auth_digitalocean\Settings\DigitalOceanAuthSettings;

/**
 * Defines a Network Plugin for Social Auth DigitalOcean.
 *
 * @package Drupal\social_auth_digitalocean\Plugin\Network
 *
 * @Network(
 *   id = "social_auth_digitalocean",
 *   social_network = "DigitalOcean",
 *   type = "social_auth",
 *   handlers = {
 *     "settings": {
 *       "class": "\Drupal\social_auth_digitalocean\Settings\DigitalOceanAuthSettings",
 *       "config_id": "social_auth_digitalocean.settings"
 *     }
 *   }
 * )
 */
class DigitalOceanAuth extends NetworkBase implements DigitalOceanAuthInterface {

  /**
   * Sets the underlying SDK library.
   *
   * @return \ChrisHemmings\OAuth2\Client\Provider\DigitalOcean|false
   *   The initialized 3rd party library instance.
   *
   * @throws SocialApiException
   *   If the SDK library does not exist.
   */
  protected function initSdk() {

    $class_name = 'ChrisHemmings\OAuth2\Client\Provider\DigitalOcean';
    if (!class_exists($class_name)) {
      throw new SocialApiException(sprintf('The DigitalOcean library for PHP League OAuth2 not found. Class: %s.', $class_name));
    }

    /* @var \Drupal\social_auth_digitalocean\Settings\DigitalOceanAuthSettings $settings */
    $settings = $this->settings;
    if ($this->validateConfig($settings)) {
      // All these settings are mandatory.
      $league_settings = [
        'clientId' => $settings->getClientId(),
        'clientSecret' => $settings->getClientSecret(),
        'redirectUri' => Url::fromRoute('social_auth_digitalocean.callback')->setAbsolute()->toString(),
      ];

      // Proxy configuration data for outward proxy.
      $proxyUrl = $this->siteSettings->get('http_client_config')['proxy']['http'];
      if ($proxyUrl) {
        $league_settings['proxy'] = $proxyUrl;
      }

      return new DigitalOcean($league_settings);
    }

    return FALSE;
  }

  /**
   * Checks that module is configured.
   *
   * @param \Drupal\social_auth_digitalocean\Settings\DigitalOceanAuthSettings $settings
   *   The DigitalOcean auth settings.
   *
   * @return bool
   *   True if module is configured.
   *   False otherwise.
   */
  protected function validateConfig(DigitalOceanAuthSettings $settings) {
    $client_id = $settings->getClientId();
    $client_secret = $settings->getClientSecret();
    if (!$client_id || !$client_secret) {
      $this->loggerFactory
        ->get('social_auth_digitalocean')
        ->error('Define Client ID and Client Secret on module settings.');

      return FALSE;
    }

    return TRUE;
  }

}
