<?php

namespace Drupal\social_auth_digitalocean\Settings;

/**
 * Defines an interface for Social Auth DigitalOcean settings.
 */
interface DigitalOceanAuthSettingsInterface {

  /**
   * Gets the client ID.
   *
   * @return string
   *   The client ID.
   */
  public function getClientId();

  /**
   * Gets the client secret.
   *
   * @return string
   *   The client secret.
   */
  public function getClientSecret();

}
