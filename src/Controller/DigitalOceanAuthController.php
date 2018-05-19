<?php

namespace Drupal\social_auth_digitalocean\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\social_api\Plugin\NetworkManager;
use Drupal\social_auth\SocialAuthDataHandler;
use Drupal\social_auth\SocialAuthUserManager;
use Drupal\social_auth_digitalocean\DigitalOceanAuthManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;

/**
 * Returns responses for Simple DigitalOcean Connect module routes.
 */
class DigitalOceanAuthController extends ControllerBase {

  /**
   * The network plugin manager.
   *
   * @var \Drupal\social_api\Plugin\NetworkManager
   */
  private $networkManager;

  /**
   * The user manager.
   *
   * @var \Drupal\social_auth\SocialAuthUserManager
   */
  private $userManager;

  /**
   * The DigitalOcean authentication manager.
   *
   * @var \Drupal\social_auth_digitalocean\DigitalOceanAuthManager
   */
  private $digitalOceanManager;

  /**
   * Used to access GET parameters.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  private $request;

  /**
   * The Social Auth Data Handler.
   *
   * @var \Drupal\social_auth\SocialAuthDataHandler
   */
  private $dataHandler;


  /**
   * The logger channel.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * DigitalOceanAuthController constructor.
   *
   * @param \Drupal\social_api\Plugin\NetworkManager $network_manager
   *   Used to get an instance of social_auth_digitalocean network plugin.
   * @param \Drupal\social_auth\SocialAuthUserManager $user_manager
   *   Manages user login/registration.
   * @param \Drupal\social_auth_digitalocean\DigitalOceanAuthManager $digitalocean_manager
   *   Used to manage authentication methods.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request
   *   Used to access GET parameters.
   * @param \Drupal\social_auth\SocialAuthDataHandler $social_auth_data_handler
   *   SocialAuthDataHandler object.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   Used for logging errors.
   */
  public function __construct(NetworkManager $network_manager,
                              SocialAuthUserManager $user_manager,
                              DigitalOceanAuthManager $digitalocean_manager,
                              RequestStack $request,
                              SocialAuthDataHandler $social_auth_data_handler,
                              LoggerChannelFactoryInterface $logger_factory) {

    $this->networkManager = $network_manager;
    $this->userManager = $user_manager;
    $this->digitalOceanManager = $digitalocean_manager;
    $this->request = $request;
    $this->dataHandler = $social_auth_data_handler;
    $this->loggerFactory = $logger_factory;

    // Sets the plugin id.
    $this->userManager->setPluginId('social_auth_digitalocean');

    // Sets the session keys to nullify if user could not logged in.
    $this->userManager->setSessionKeysToNullify(['access_token', 'oauth2state']);
    $this->setting = $this->config('social_auth_digitalocean.settings');
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('plugin.network.manager'),
      $container->get('social_auth.user_manager'),
      $container->get('social_auth_digitalocean.manager'),
      $container->get('request_stack'),
      $container->get('social_auth.data_handler'),
      $container->get('logger.factory')
    );
  }

  /**
   * Response for path 'user/login/digitalocean'.
   *
   * Redirects the user to DigitalOcean for authentication.
   */
  public function redirectToDigitalOcean() {
    /* @var \ChrisHemmings\OAuth2\Client\Provider\DigitalOcean|false $digitalocean */
    $digitalOcean = $this->networkManager->createInstance('social_auth_digitalocean')->getSdk();

    // If DigitalOcean client could not be obtained.
    if (!$digitalOcean) {
      drupal_set_message($this->t('Social Auth DigitalOcean not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // DigitalOcean service was returned, inject it to $digitaloceanManager.
    $this->digitalOceanManager->setClient($digitalOcean);

    // Generates the URL where the user will be redirected for authentication.
    $auth_url = $this->digitalOceanManager->getAuthorizationUrl();

    $state = $this->digitalOceanManager->getState();

    $this->dataHandler->set('oauth2state', $state);

    return new TrustedRedirectResponse($auth_url);
  }

  /**
   * Response for path 'user/login/digitalocean/callback'.
   *
   * DigitalOcean returns the user here after user has authenticated.
   */
  public function callback() {
    // Checks if user cancel authentication via DigitalOcean.
    $error = $this->request->getCurrentRequest()->get('error');
    if ($error == 'access_denied') {
      drupal_set_message($this->t('You could not be authenticated.'), 'error');
      return $this->redirect('user.login');
    }

    /* @var \ChrisHemmings\OAuth2\Client\Provider\DigitalOcean|false $digitalOcean */
    $digitalOcean = $this->networkManager->createInstance('social_auth_digitalocean')->getSdk();

    // If DigitalOcean client could not be obtained.
    if (!$digitalOcean) {
      drupal_set_message($this->t('Social Auth DigitalOcean not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    $state = $this->dataHandler->get('oauth2state');

    // Retrieves $_GET['state'].
    $retrievedState = $this->request->getCurrentRequest()->query->get('state');
    if (empty($retrievedState) || ($retrievedState !== $state)) {
      $this->userManager->nullifySessionKeys();
      drupal_set_message($this->t('DigitalOcean login failed. Unvalid OAuth2 State.'), 'error');
      return $this->redirect('user.login');
    }

    $this->digitalOceanManager->setClient($digitalOcean)->authenticate();

    // Saves access token to session.
    $this->dataHandler->set('access_token', $this->digitalOceanManager->getAccessToken());

    // Gets user's info from DigitalOcean API.
    /* @var \ChrisHemmings\OAuth2\Client\Provider\DigitalOceanResourceOwner $profile */
    if (!$profile = $this->digitalOceanManager->getUserInfo()) {
      drupal_set_message($this->t('DigitalOcean login failed, could not load DigitalOcean profile. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // Gets (or not) extra initial data.
    $data = $this->userManager->checkIfUserExists($profile->getId()) ? NULL : $this->digitalOceanManager->getExtraDetails();

    // If user information could be retrieved.
    return $this->userManager->authenticateUser($profile->getId(), $profile->getEmail(), $profile->getId(), $this->digitalOceanManager->getAccessToken(), FALSE, $data);
  }

}
