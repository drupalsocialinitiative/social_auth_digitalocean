<?php

namespace Drupal\social_auth_digitalocean\Settings;

/**
 * Defines an interface for Social Auth Digitalocean settings.
 */
interface DigitaloceanAuthSettingsInterface {

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
