<?php

namespace Drupal\social_auth_digitalocean\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Drupal\social_auth\Form\SocialAuthSettingsForm;

/**
 * Settings form for Social Auth DigitalOcean.
 */
class DigitalOceanAuthSettingsForm extends SocialAuthSettingsForm {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'social_auth_digitalocean_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return array_merge(
      parent::getEditableConfigNames(),
      ['social_auth_digitalocean.settings']
    );
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('social_auth_digitalocean.settings');

    $form['digitalocean_settings'] = [
      '#type' => 'details',
      '#title' => $this->t('DigitalOcean Client settings'),
      '#open' => TRUE,
      '#description' => $this->t('You need to first create a DigitalOcean App at <a href="@digitalocean-dev">@digitalocean-dev</a>', ['@digitalocean-dev' => 'https://cloud.digitalocean.com/settings/api/applications']),
    ];

    $form['digitalocean_settings']['client_id'] = [
      '#type' => 'textfield',
      '#required' => TRUE,
      '#title' => $this->t('Client ID'),
      '#default_value' => $config->get('client_id'),
      '#description' => $this->t('Copy the Client ID here.'),
    ];

    $form['digitalocean_settings']['client_secret'] = [
      '#type' => 'textfield',
      '#required' => TRUE,
      '#title' => $this->t('Client Secret'),
      '#default_value' => $config->get('client_secret'),
      '#description' => $this->t('Copy the Client Secret here.'),
    ];

    $form['digitalocean_settings']['authorized_redirect_url'] = [
      '#type' => 'textfield',
      '#disabled' => TRUE,
      '#title' => $this->t('Application Callback URL'),
      '#description' => $this->t('Copy this value to <em>Application Callback URL</em> field of your DigitalOcean App settings.'),
      '#default_value' => Url::fromRoute('social_auth_digitalocean.callback')->setAbsolute()->toString(),
    ];

    $form['digitalocean_settings']['advanced'] = [
      '#type' => 'details',
      '#title' => $this->t('Advanced settings'),
      '#open' => FALSE,
    ];

    $form['digitalocean_settings']['advanced']['scopes'] = [
      '#type' => 'radios',
      '#title' => $this->t('Scopes for API call'),
      '#default_value' => $config->get('scopes'),
      '#options' => ['read' => 'read', 'read write' => 'read write'],
      '#description' => $this->t('Select the scope to be requested<br>
                                  You can see a description of the scopes <a href="@scopes">here</a>.', ['@scopes' => 'https://developers.digitalocean.com/documentation/oauth/#scopes']),
    ];

    $form['digitalocean_settings']['advanced']['endpoints'] = [
      '#type' => 'textarea',
      '#title' => $this->t('API calls to be made to collect data'),
      '#default_value' => $config->get('endpoints'),
      '#description' => $this->t('Define the endpoints to be requested when user authenticates with DigitalOcean for the first time<br>
                                  Enter each endpoint in different lines in the format <em>endpoint</em>|<em>name_of_endpoint</em>.<br>
                                  <b>For instance:</b><br>
                                  /v2/actions|user_actions<br>
                                  /v2/volumes|user_volumes'),
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    $this->config('social_auth_digitalocean.settings')
      ->set('client_id', $values['client_id'])
      ->set('client_secret', $values['client_secret'])
      ->set('scopes', $values['scopes'])
      ->set('endpoints', $values['endpoints'])
      ->save();

    parent::submitForm($form, $form_state);
  }

}
