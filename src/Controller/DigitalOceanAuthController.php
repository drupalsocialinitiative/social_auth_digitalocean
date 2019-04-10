<?php

namespace Drupal\social_auth_digitalocean\Controller;

use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Render\RendererInterface;
use Drupal\social_api\Plugin\NetworkManager;
use Drupal\social_auth\Controller\OAuth2ControllerBase;
use Drupal\social_auth\SocialAuthDataHandler;
use Drupal\social_auth\User\UserAuthenticator;
use Drupal\social_auth_digitalocean\DigitalOceanAuthManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Returns responses for Simple DigitalOcean Connect module routes.
 */
class DigitalOceanAuthController extends OAuth2ControllerBase {

  /**
   * DigitalOceanAuthController constructor.
   *
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   * @param \Drupal\social_api\Plugin\NetworkManager $network_manager
   *   Used to get an instance of social_auth_digitalocean network plugin.
   * @param \Drupal\social_auth\User\UserAuthenticator $user_authenticator
   *   Used to manage user authentication/registration.
   * @param \Drupal\social_auth_digitalocean\DigitalOceanAuthManager $digitalocean_manager
   *   Used to perform authentication tasks with provider.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request
   *   Used to access GET parameters.
   * @param \Drupal\social_auth\SocialAuthDataHandler $data_handler
   *   The Social Auth data handler.
   * @param \Drupal\Core\Render\RendererInterface $renderer
   *   Used to handle metadata for redirection to authentication URL.
   */
  public function __construct(MessengerInterface $messenger,
                              NetworkManager $network_manager,
                              UserAuthenticator $user_authenticator,
                              DigitalOceanAuthManager $digitalocean_manager,
                              RequestStack $request,
                              SocialAuthDataHandler $data_handler,
                              RendererInterface $renderer) {

    parent::__construct('Social Auth DigitalOcean', 'social_auth_digitalocean',
                        $messenger, $network_manager, $user_authenticator,
                        $digitalocean_manager, $request, $data_handler,
                        $renderer);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('messenger'),
      $container->get('plugin.network.manager'),
      $container->get('social_auth.user_authenticator'),
      $container->get('social_auth_digitalocean.manager'),
      $container->get('request_stack'),
      $container->get('social_auth.data_handler'),
      $container->get('renderer')
    );
  }

  /**
   * Response for path 'user/login/digitalocean/callback'.
   *
   * DigitalOcean returns the user here after user has authenticated.
   */
  public function callback() {

    // Checks if authentication failed.
    if ($this->request->getCurrentRequest()->query->has('error')) {
      $this->messenger->addError($this->t('You could not be authenticated.'));

      return $this->redirect('user.login');
    }

    /* @var \ChrisHemmings\OAuth2\Client\Provider\DigitalOceanResourceOwner|null $profile */
    $profile = $this->processCallback();

    // If authentication was successful.
    if ($profile !== NULL) {

      // Gets (or not) extra initial data.
      $data = $this->userAuthenticator->checkProviderIsAssociated($profile->getId()) ? NULL : $this->providerManager->getExtraDetails();

      return $this->userAuthenticator->authenticateUser($profile->getId(),
                                                        $profile->getEmail(),
                                                        $profile->getId(),
                                                        $this->providerManager->getAccessToken(),
                                             FALSE,
                                                        $data);
    }

    return $this->redirect('user.login');
  }

}
