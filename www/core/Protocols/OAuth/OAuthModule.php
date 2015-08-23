<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 * 
 */

namespace SimpleID\Protocols\OAuth;

use Psr\Log\LogLevel;
use SimpleID\Auth\AuthManager;
use SimpleID\Module;
use SimpleID\ModuleManager;
use SimpleID\Store\StoreManager;
use SimpleID\Util\SecurityToken;

/**
 * The module for authentication using OAuth.
 *
 * This module contains basic functions for process authorisation
 * requests and granting access tokens.
 */
class OAuthModule extends Module {

    const CHECKID_OK = 127;
    const CHECKID_RETURN_TO_SUSPECT = 3;
    const CHECKID_APPROVAL_REQUIRED = 2;
    const CHECKID_REENTER_CREDENTIALS = -1;
    const CHECKID_LOGIN_REQUIRED = -2;
    const CHECKID_IDENTITIES_NOT_MATCHING = -3;
    const CHECKID_IDENTITY_NOT_EXIST = -4;
    const CHECKID_PROTOCOL_ERROR = -127;

    const DEFAULT_SCOPE = 'tag:simpleid.sf.net,2014:oauth:default';

    static private $oauth_scope_settings = NULL;

    static private $scope_settings = NULL;

    protected $oauth;

    protected $mgr;

    static function routes($f3) {
        $f3->route('GET @oauth_auth: /oauth/auth', 'SimpleID\Protocols\OAuth\OAuthModule->auth');
        $f3->route('POST @oauth_token: /oauth/token', 'SimpleID\Protocols\OAuth\OAuthModule->token');
        $f3->route('POST @oauth_consent: /oauth/consent', 'SimpleID\Protocols\OAuth\OAuthModule->consent');
        $f3->route('POST /oauth/revoke', 'SimpleID\Protocols\OAuth\OAuthModule->revoke');
    }

    public function __construct() {
        parent::__construct();
        $this->oauth = OAuthManager::instance();
        $this->mgr = ModuleManager::instance();
    }

    /**
     * Initialises this module.
     *
     * @see SimpleID\API\ModuleHooks::initHook()
     */
    public function initHook() {
        $scope_settings = $this->mgr->invokeAll('scopes');
        self::$oauth_scope_settings = $scope_settings['oauth'];
    }

    /**
     * Prepares an OAuth authorisation request for processing.
     *
     * This function checks the request for protocol compliance via
     * {@link checkAuthRequest()} before passing it to {@link processAuthRequest()} 
     * for processing.
     *
     * @see checkAuthRequest()
     * @see processAuthRequest()
     * @since 2.0
     */
    public function auth() {
        $this->checkHttps('redirect');

        $request = new Request($this->f3->get('GET'), array());
        
        $this->logger->log(LogLevel::INFO, 'OAuth authorisation request: ', $request->toArray());
        
        $response = new Response($request);
        
        $this->mgr->invokeAll('oAuthResolveAuthRequest', $request, $response);
        if ($response->isError()) {
            if (isset($request['redirect_uri'])) {
                $response->renderRedirect();
            } else {
                $this->fatalError($this->t('Protocol Error: %error_code', array('%error_code' => $response['error'])));
            }
            return;
        }
        
        $this->checkAuthRequest($request, $response);

        $this->mgr->invokeAll('oAuthCheckAuthRequest', $request, $response);
        if ($response->isError()) {
            if (isset($request['redirect_uri'])) {
                $response->renderRedirect();
            } else {
                $this->fatalError($this->t('Protocol Error: %error_code', array('%error_code' => $response['error'])));
            }
            return;
        }

        $this->processAuthRequest($request, $response);
    }

    /**
     * Checks an OAuth authorisation request for protocol compliance.
     *
     * @param Request $request the original request
     * @param Response $response the OAuth response
     * @see processAuthRequest()
     *
     */
    protected function checkAuthRequest($request, $response) {
        $store = StoreManager::instance();

        // 1. response_type (pass 1 - check that it exists)
        if (!isset($request['response_type'])) {
            $this->logger->log(LogLevel::ERROR, 'Protocol Error: response_type not set.');
            $this->fatalError($this->t('Protocol Error: response_type not set.'));
            return;
        }
        
        $response_types = preg_split('/\s+/', $request['response_type']);
        
        if (in_array('token', $response_types)) $response->setResponseType(Response::FRAGMENT_RESPONSE_TYPE);

        // 2. client_id (pass 1 - check that it exists)
        if (!isset($request['client_id'])) {
            $this->logger->log(LogLevel::ERROR, 'Protocol Error: client_id not set');
            if (isset($request['redirect_uri'])) {
                $response->setError('invalid_request', 'client_id not set')->renderRedirect();
            } else {
                $this->fatalError($this->t('Protocol Error: client_id not set'));
            }
            return;
        }
        
        $client = $store->loadClient($request['client_id'], 'SimpleID\Protocols\OAuth\OAuthClient');
        if ($client == NULL) {
            $this->logger->log(LogLevel::ERROR, 'Client with client_id not found: ' . $request['client_id']);
            if (isset($request['redirect_uri'])) {
                $response->setError('invalid_request', 'client not found')->renderRedirect();
            } else {
                $this->fatalError($this->t('Protocol Error: Client not found'));
            }
            return;
        }
        
        // 3. redirect_uri
        if (isset($request['redirect_uri'])) {
            // Validate against client registration for public clients and implicit grant types
            $redirect_uri_found = false;

            $request_redirect_uri_has_query = (parse_url($request['redirect_uri'], PHP_URL_QUERY) != null);
            
            foreach ($client['oauth']['redirect_uris'] as $test_redirect_uri) {
                $test_redirect_uri_has_query = (parse_url($test_redirect_uri, PHP_URL_QUERY) != null);
                if (!$test_redirect_uri_has_query && $request_redirect_uri_has_query) continue;

                if (strcasecmp(substr($request['redirect_uri'], 0, strlen($test_redirect_uri)), $test_redirect_uri) === 0) {
                    $redirect_uri_found = true;
                    break;
                }
            }
            
            if (!$redirect_uri_found) {
                $this->logger->log(LogLevel::ERROR, 'Incorrect redirect URI: ' . $request['redirect_uri']);
                $this->fatalError($this->t('Protocol Error: Incorrect redirect URI'));
                return;
            }
        } elseif (isset($client['oauth']['redirect_uris'])) {
            if (is_string($client['oauth']['redirect_uris'])) {
                $response->setRedirectURI($client['oauth']['redirect_uris']);
            } elseif (count($client['oauth']['redirect_uris']) == 1) {
                $response->setRedirectURI($client['oauth']['redirect_uris'][0]);
            } else {
                $this->logger->log(LogLevel::ERROR, 'Protocol Error: redirect_uri not specified in request when multiple redirect_uris are registered');
                $this->fatalError($this->t('Protocol Error: redirect_uri not specified in request when multiple redirect_uris are registered'));
                return;
            }
        } else {
            $this->logger->log(LogLevel::ERROR, 'Protocol Error: redirect_uri not specified in request or client registration');
            $this->fatalError($this->t('Protocol Error: redirect_uri not specified in request or client registration'));
            return;
        }
        
        // 4. response_type (pass 2 - check that all are supported)
        $supported_response_types = $this->mgr->invokeAll('oAuthResponseTypes');
        foreach ($response_types as $response_type) {
            if (!in_array($response_type, $supported_response_types)) {
                $this->logger->log(LogLevel::ERROR, 'Protocol Error: unsupported response_type: ' . $response_type);
                $response->setError('unsupported_response_type', 'unsupported response_type: ' . $response_type)->renderRedirect();
                return;
            }
        }
    }

    /**
     * Processes an OAuth authorisation request that has been prepared by {@link checkAuthRequest()}.
     *
     * It is important that all requests are prepared by {@link checkAuthRequest()}
     * instead of being passed directly to this function, as this function assumes that the request
     * has been checked for protocol compliance.
     *
     * @param Request $request the original request
     * @param Response $response the OAuth response
     * @see checkAuthRequest()
     *
     */
    protected function processAuthRequest($request, $response) {
        $this->logger->log(LogLevel::INFO, 'Expanded OAuth authorisation request: ', $request->toArray());

        $core_result = $this->checkIdentity($request);

        $results = $this->mgr->invokeAll('oAuthProcessAuthRequest', $request, $response);
        
        // Filter out nulls
        $results = array_merge(array_diff($results, array(NULL)));
            
        // Prepend the core_result and take the lowest value
        array_unshift($results, $core_result);
        $result = min($results);
        
        switch ($result) {
            case self::CHECKID_OK:
                $this->logger->log(LogLevel::INFO, 'CHECKID_OK');
                
                if (isset($request['scope'])) {
                    $scopes = $request->paramToArray('scope');
                } else {
                    $scopes = array(self::DEFAULT_SCOPE);
                }
                $this->grantAuth($request, $response, $scopes);
                break;
            case self::CHECKID_APPROVAL_REQUIRED:
                $this->logger->log(LogLevel::INFO, 'CHECKID_APPROVAL_REQUIRED');
                if ($request->immediate) {
                    $response->setError('consent_required', 'Consent required')->renderRedirect();
                } else {
                    $this->consentForm($request, $response);
                }
                break;
            case self::CHECKID_REENTER_CREDENTIALS:
            case self::CHECKID_LOGIN_REQUIRED:
                $this->logger->log(LogLevel::INFO, 'CHECKID_LOGIN_REQUIRED');
                if ($request->immediate) {
                    $response->setError('login_required', 'Login required')->renderRedirect();
                } else {
                    $token = new SecurityToken();
                    $state = array('rt' => '/oauth/auth', 'rq' => $request->toArray());
                    $form_state = array(
                        'rq' => $request->toArray(),
                        'mode' => AuthManager::MODE_CREDENTIALS,
                        'auth_skip_activity' => true
                    );
                    if ($result == self::CHECKID_REENTER_CREDENTIALS) $form_state['mode'] = AuthManager::MODE_REENTER_CREDENTIALS;

                    $auth_module = $this->mgr->getModule('SimpleID\Auth\AuthModule');
                    $auth_module->loginForm(array(
                        'destination' => 'continue/' . rawurlencode($token->generate($state))
                    ), $form_state);
                    exit;
                }
                break;
            case self::CHECKID_INSUFFICIENT_TRUST:
                $this->logger->log(LogLevel::INFO, 'CHECKID_INSUFFICIENT_TRUST');
                $response->setError('invalid_request', 'SimpleID does not support the requested level of trust')->renderRedirect();
                break;
        }
    }


    /**
     * Determines whether the current user has granted authorisation to the OAuth/OpenID Connect
     * client.
     *
     * @param Request $request the OAuth authorisation request
     * @return int one of CHECKID_OK, CHECKID_APPROVAL_REQUIRED, CHECKID_LOGIN_REQUIRED, CHECKID_INSUFFICIENT_TRUST
     * or CHECKID_USER_DENIED
     */
    protected function checkIdentity($request) {
        $auth = AuthManager::instance();
        $store = StoreManager::instance();
        
        // Check 1: Is the user logged into SimpleID as any user?
        if (!$auth->isLoggedIn()) {
            return self::CHECKID_LOGIN_REQUIRED;
        } else {
            $user = $auth->getUser();
            $uid = $user['uid'];
        }
        
        // Check 2: See if the user has consents saved for this client
        $cid = $request['client_id'];
        
        $client_prefs = isset($user->clients[$cid]) ? $user->clients[$cid] : NULL;
        
        if (isset($client_prefs['consents']['oauth'])) {
            $consents = $client_prefs['consents']['oauth'];
        } else {
            return self::CHECKID_APPROVAL_REQUIRED;
        }

        // Check 3: Compare consent given against requested scope
        if (isset($request['scope'])) {
            $scopes = $request->paramToArray('scope');
        } else {
            $scopes = array(self::DEFAULT_SCOPE);
        }
        if (count(array_diff($scopes, $consents)) > 0) return self::CHECKID_APPROVAL_REQUIRED;

        return self::CHECKID_OK;
    }

    /**
     * Grants an authorisation request by issuing the appropriate response.  The response
     * may take in the form of an authorization code, an access token or other
     * parameters
     *
     * @param Request $request the authorisation request
     * @param Response $response the authorisation response
     * @param array $scopes the requested scope
     */
    protected function grantAuth($request, $response, $scopes = NULL) {
        $store = StoreManager::instance();

        $user = AuthManager::instance()->getUser();
        $client = $store->loadClient($request['client_id'], 'SimpleID\Protocols\OAuth\OAuthClient');
        if ($scopes == NULL) {
            if (isset($request['scope'])) {
                $scopes = $request->paramToArray('scope');
            } else {
                $scopes = array(self::DEFAULT_SCOPE);
            }
        }

        $authorization = $store->loadAuth(Authorization::buildID($user, $client));

        if ($authorization == null) {
            $authorization = new Authorization($user, $client, $scopes);
        } else {
            $authorization->setScope($scopes);
        }

        $activity = array(
            'type' => 'app',
            'id' => $client->getStoreID(),
            'time' => time()
        );
        if ($this->f3->exists('IP')) $activity['remote'] = $this->f3->get('IP');
        $user->addActivity($cid, $activity);

        if ($request->paramContains('response_type', 'code')) {
            $response['code'] = $authorization->issueCode((isset($request['redirect_uri'])) ? $request['redirect_uri'] : NULL);
        }

        if ($request->paramContains('response_type', 'token')) {
            $response->loadData($authorization->issueAccessToken($scopes, SIMPLEID_SHORT_TOKEN_EXPIRES_IN));
            $this->mgr->invokeAll('oAuthToken', 'implicit', $authorization, $request, $response, $scopes);
        }

        $this->mgr->invokeAll('oAuthGrantAuth', $authorization, $request, $response, $scopes);

        $store->saveAuth($authorization);
        $store->saveUser($user);

        $this->logger->log(LogLevel::DEBUG, 'Authorization granted: ', $response->toArray());

        $response->renderRedirect();
    }

    /**
     * Processes an OAuth token request.
     *
     * @since 2.0
     */
    public function token() {
        $request = new Request($this->f3->get('POST'));
        $response = new Response($request);
        
        $this->checkHttps('error');
        
        $this->logger->log(LogLevel::INFO, 'OAuth token request: ', $request->toArray());
        
        if (!isset($request['grant_type'])) {
            $this->logger->log(LogLevel::ERROR, 'Protocol Error: grant_type not set.');
            $response->setError('invalid_request', 'grant_type not set');
            $response->renderJSON();
            return;
        }
        
        $this->oauth->initClient(true);
        $client = $this->oauth->getClient();

        if (!$this->oauth->isClientAuthenticated(true, isset($client['oauth']['token_endpoint_auth_method']) ? $client['oauth']['token_endpoint_auth_method'] : null)) {
            $this->logger->log(LogLevel::ERROR, 'Client authentication failed');
            $response->setError('invalid_client', 'client authentication failed');
            $response->renderJSON();
            return;
        }

        $grant_types = (isset($client['oauth']['grant_types'])) ? $client['oauth']['grant_types'] : array('authorization_code');
        if (!in_array($request['grant_type'], $grant_types)) {
            $this->logger->log(LogLevel::ERROR, 'Grant type not registered by client');
            $response->setError('unauthorized_client', 'Grant type not registered by client');
            $response->renderJSON();
            return;
        }
        
        switch ($request['grant_type']) {
            case 'authorization_code':
                $authorization = $this->tokenFromCode($request, $response);
                break;
            case 'refresh_token':
                $authorization = $this->tokenFromRefreshToken($request, $response);
                break;
            case 'password':
            case 'client_credentials':
                // Not allowed
            default:
                // Extensions can be put here.
                $this->logger->log(LogLevel::ERROR, 'Token request failed: unsupported grant type');
                $response->setError('unsupported_grant_type', 'grant type ' . $grant_type . ' is not supported');
                break;
        }

        $this->logger->log(LogLevel::DEBUG, 'Token response: ', $response->toArray());
        $response->renderJSON();
    }

    /**
     * Processes an OAuth token request where an authorisation code is supplied.
     *
     * @param Request $request the OAuth token request
     * @param Response $response the OAuth response
     * @since 2.0
     */
    protected function tokenFromCode($request, $response) {
        // 1. Check code parameter
        if (!isset($request['code']) || ($request['code'] == '')) {
            $this->logger->log(LogLevel::ERROR, 'Token request failed: code not set');
            $response->setError('invalid_request', 'code not set');
            return;
        }

        // 2. Load the authorization and delete all tokens with this source
        $code = Code::decode($request['code']);
        $authorization = $code->getAuthorization();
        if ($authorization == null) {
            $this->logger->log(LogLevel::ERROR, 'Token request failed: Authorisation not found or expired');
            $response->setError('invalid_grant', 'Authorization code not found or expired');
            return;
        }
        $authorization->revokeTokensFromSource($code);
        

        // 3. Check for validity
        if (!$code->isValid()) {
            $this->logger->log(LogLevel::ERROR, 'Token request failed: Authorisation code not found or expired: ' . $request['code']);
            $response->setError('invalid_grant', 'Authorization code not found or expired');
            return;
        }

        // 4. Check request URI
        if ($code->getRedirectURI()) {
            if (!isset($request['redirect_uri']) || ($code->getRedirectURI() != $request['redirect_uri'])) {
                $this->logger->log(LogLevel::ERROR, 'Token request failed: redirect_uri in request <' . $request['redirect_uri'] . '> does not match authorisation code <' . $code->getRedirectURI() . '>');
                $response->setError('invalid_grant', 'redirect_uri does not match');
                return;
            }
        }
        $scope = $code->getScope();

        // If we issue, we delete the code so that it can't be used again
        $code->clear();

        $response->loadData($authorization->issueTokens($scope, SIMPLEID_SHORT_TOKEN_EXPIRES_IN, $code));

        // Call modules
        $this->mgr->invokeAll('oAuthToken', 'authorization_code', $authorization, $request, $response, $scope);

        return $authorization;
    }

    /**
     * Processes an OAuth refresh token request.
     *
     * @param Request $request the OAuth token request
     * @param Response $response the response
     */
    protected function tokenFromRefreshToken($request, $response) {
        $store = StoreManager::instance();
        $client = $this->oauth->getClient();

        if (!isset($request['refresh_token']) || ($request['refresh_token'] == '')) {
            $this->logger->log(LogLevel::ERROR, 'Token request failed: refresh_token not set');
            $response->setError('invalid_request', 'refresh_token not set');
            return;
        }

        $refresh_token = RefreshToken::decode($request['refresh_token']);
        if (!$refresh_token->isValid()) {
            $this->logger->log(LogLevel::ERROR, 'Token request failed: Refresh token not valid');
            $response->setError('invalid_grant', 'Refresh token not valid');
            return;
        }

        $authorization = $refresh_token->getAuthorization();
        if ($authorization->getClient()->getStoreID() != $client->getStoreID()) {
            $this->logger->log(LogLevel::ERROR, 'Token request failed: this client (' . $client->getStoreID() . ') does not match the client stored in refresh token (' . $authorization->getClient()->getStoreID() . ')');
            $response->setError('invalid_grant', 'this client does not match the client stored in refresh token');
            $response->renderJSON();
            return;
        }
        $authorization->revokeTokensFromSource($refresh_token);
        
        $scope = $refresh_token->getScope();

        // If we issue, we delete the old refresh token so that it can't be used again
        $refresh_token->revoke();
        $authorization->resetAuthState();
        $store->saveAuth($authorization);

        $response->loadData($authorization->issueTokens($scope, SIMPLEID_SHORT_TOKEN_EXPIRES_IN, $refresh_token));

        // Call modules
        $this->mgr->invokeAll('oAuthToken', 'refresh_token', $authorization, $request, $response, $scope);

        return $authorization;
    }


    /**
     * Provides a form for user authorisation of an OAuth client.
     *
     * @param Request $request the OAuth request
     * @param Response $response the OAuth response
     * @since 2.0
     */
    protected function consentForm($request, $response) {
        $store = StoreManager::instance();
        $tpl = new \Template();

        $client = $store->loadClient($request['client_id'], 'SimpleID\Protocols\OAuth\OAuthClient');

        $form_state = array(
            'rq' => $request,
            'rs' => $response,
        );
        
        $application_name = $client->getDisplayName();
        $application_type = (isset($client['oauth']['application_type'])) ? $client['oauth']['application_type'] : '';
        
        $this->f3->set('application_name', $application_name);
        
        if (isset($client['logo_url'])) {
            $this->f3->set('logo_url', $client['logo_url']);
        }
        
        if (isset($request['scope'])) {
            $scopes = $request->paramToArray('scope');
        } else {
            $scopes = array(self::DEFAULT_SCOPE);
        }
        usort($scopes, array($this, 'sortScopes'));
        
        $scope_list = array();
        foreach ($scopes as $scope) {
            $scope_list[$scope] = (isset(self::$oauth_scope_settings[$scope]['description'])) ? self::$oauth_scope_settings[$scope]['description'] : 'scope ' . $scope;
        }
        $this->f3->set('scope_list', $scope_list);

        if ($client->isDynamic()) {
            $this->f3->set('dynamic_label', $this->t('Warning: %application_name did not pre-register with SimpleID.  Its identity has not been confirmed.', array('%application_name' => $application_name)));
            $this->f3->set('client_dynamic', 'client-dynamic');
        }

        $client_info = array();
        if (isset($client['oauth']['website'])) {
            $client_info[] = $this->t('You can visit this application\'s web site at <a href="%url">%url</a>.', array('%url' => $client['oauth']['website']));
        }
        if (isset($client['oauth']['policy_url'])) {
            $client_info[] = $this->t('You can view this application\'s policy on the use of your data at <a href="%url">%url</a>.', array('%url' => $client['oauth']['policy_url']));
        }
        if (isset($client['oauth']['tos_url'])) {
            $client_info[] = $this->t('You can view this application\'s terms of service at <a href="%url">%url</a>.', array('%url' => $client['oauth']['tos_url']));
        }
        if (isset($client['oauth']['contacts'])) {
            $contacts = array();
            
            if (is_array($client['oauth']['contacts'])) {
                foreach ($client['oauth']['contacts'] as $contact) {
                    $contacts[] = '<a href="mailto:' . $this->rfc3986_urlencode($contact) . '">' . $this->f3->clean($contact) . '</a>';
                }
            } else {
                $contacts[] = '<a href="mailto:' . $this->rfc3986_urlencode($client['oauth']['contacts']) . '">' . $this->f3->clean($client['oauth']['contacts']) . '</a>';
            }
            
            $client_info[] = $this->t('You can email the developer of this application at: !contacts.', array('!contacts' => implode(', ', $contacts)));
        }
        $this->f3->set('client_info', $client_info);
        $this->f3->set('client_info_label', $this->t('More information'));
        
        $this->f3->set('request_label', $this->t('<strong class="@application_type">%application_name</strong> is requesting access to:', array('@application_type' => $application_type, '%application_name' => $application_name)));
        $this->f3->set('dashboard_label', $this->t('You can revoke access at any time under <strong>Dashboard</strong>.'));
        $this->f3->set('oauth_consent_label', $this->t('Don\'t ask me again for %application_name.', array('%application_name' => $application_name)));
        $this->f3->set('allow_button', $this->t('Allow'));
        $this->f3->set('deny_button', $this->t('Deny'));
        
        $token = new SecurityToken();
        $this->f3->set('tk', $token->generate('oauth_consent', SecurityToken::OPTION_BIND_SESSION));
        $this->f3->set('fs', $token->generate($form_state));

        $this->f3->set('logout_destination', '/continue/' . rawurlencode($token->generate($request->toArray())));
        $this->f3->set('user_header', true);
        $this->f3->set('framekiller', true);
        $this->f3->set('title', $this->t('OAuth Login'));
        $this->f3->set('page_class', 'dialog-page');
        $this->f3->set('layout', 'oauth_consent.html');

        $forms = $this->mgr->invokeAll('oAuthConsentForm', $form_state);
        uasort($forms, function($a, $b) { if ($a['weight'] == $b['weight']) { return 0; } return ($a['weight'] < $b['weight']) ? -1 : 1; });
        $this->f3->set('forms', $forms);
        
        header('X-Frame-Options: DENY');
        print $tpl->render('page.html');
    }


    /**
     * Processes a user response from the {@link consentForm()} function.
     *
     * @since 2.0
     */
    function consent() {
        $auth = AuthManager::instance();
        $token = new SecurityToken();
        $store = StoreManager::instance();
    
        if (!$auth->isLoggedIn()) {
            $auth_module = $this->mgr->getModule('SimpleID\Auth\AuthModule');
            $auth_module->loginForm();
            return;
        }
        $user = $auth->getUser();
        
        $form_state = $token->getPayload($this->f3->get('POST.fs'));
        $request = $form_state['rq'];
        $response = $form_state['rs'];

        if (!$token->verify($this->f3->get('POST.tk'), 'oauth_consent')) {
            $this->logger->log(LogLevel::WARNING, 'Security token ' . $this->f3->get('POST.tk') . ' invalid.');
            $this->f3->set('message', $this->t('SimpleID detected a potential security attack.  Please try again.'));
            $this->consentForm($request, $response);
            return;
        }
        
        if ($this->f3->get('POST.op') == $this->t('Deny')) {
            $response->setError('access_denied')->renderRedirect();
            return;
        } else {
            $this->mgr->invokeRefAll('oAuthConsentFormSubmit', $form_state);

            $client = $store->loadClient($request['client_id'], 'SimpleID\Protocols\OAuth\OAuthClient');
            $cid = $client->getStoreID();
            $now = time();

            $consents = array('oauth' => $this->f3->get('POST.prefs.consents.oauth'));

            if (isset($user->clients[$cid])) {
                $prefs = $user->clients[$cid];
            } else {
                $prefs = array(
                    'oauth' => array(),
                    'store_id' => $client->getStoreID(),
                    'display_name' => $client->getDisplayName(),
                    'display_html' => $client->getDisplayHTML(),
                    'first_time' => $now,
                    'consents' => array(),
                );
            }

            $prefs['last_time'] = $now;
            $prefs['consents'] = array_merge($prefs['consents'], $consents);

            if ($this->f3->exists('POST.prefs.oauth.prompt_none') && ($this->f3->exists('POST.prefs.oauth.prompt_none') == 'true')) {
                $prefs['oauth']['prompt_none'] = true;
            }
                
            $user->clients[$cid] = $prefs;
            $store->saveUser($user);
        }

        $this->processAuthRequest($request, $response);
    }

    /** @see SimpleID\API\OAuthHooks::scopesHook() */
    public function scopesHook() {
        if (self::$scope_settings == NULL) {
            self::$scope_settings = array(
                'oauth' => array(
                    self::DEFAULT_SCOPE => array(
                        'description' => $this->t('know who you are'),
                        //'required' => true
                    )
                )
            );
        }
        return self::$scope_settings;
    }

    /** @see SimpleID\API\OAuthHooks::oAuthResponseTypesHook() */
    public function oAuthResponseTypesHook() {
        return array('token', 'code');
    }

    /** @see SimpleID\API\MyHooks::revokeAppHook() */
    public function revokeAppHook($cid) {
        $auth = AuthManager::instance();
        $store = StoreManager::instance();
        
        $user = $auth->getUser();
        $client = $store->loadClient($cid, 'SimpleID\Protocols\OAuth\OAuthClient');

        $aid = Authorization::buildID($user, $client);

        $authorization = $store->loadAuth($aid);

        if ($authorization != null) {
            $authorization->revokeAllTokens();
            $store->deleteAuth($authorization);
        }
    }


    /**
     * Encodes a URL using RFC 3986.
     *
     * PHP's rawurlencode function encodes a URL using RFC 1738.  RFC 1738 has been
     * updated by RFC 3986, which change the list of characters which needs to be
     * encoded.
     *
     * Strictly correct encoding is required for various purposes, such as OAuth
     * signature base strings.
     *
     * @param string $s the URL to encode
     * @return string the encoded URL
     */
    private function rfc3986_urlencode($s) {
        return str_replace('%7E', '~', rawurlencode($s));
    }


    /**
     * A callback function for use by usort() to sort scopes to be displayed on
     * a consent form.
     *
     * This function determines the sort order as follows:
     *
     * 1. If the relevant entry has a
     *    key called `required` and is set to true, this scope is placed first
     * 2. If the relevant entry has a
     *    key called `weight`, it is sorted using that weight.
     * 3. Otherwise, scopes are sorted in alphabetical order
     *
     * @param array $a
     * @param array $b
     * @return int
     * @since 2.0
     */
    static function sortScopes($a, $b) {
        $a_required = (isset(self::$oauth_scope_settings[$a]['required'])) ? self::$oauth_scope_settings[$a]['required'] : false;
        $b_required = (isset(self::$oauth_scope_settings[$b]['required'])) ? self::$oauth_scope_settings[$b]['required'] : false;
        
        if ($a_required && !$b_required) return -1;
        if ($b_required && !$a_required) return 1;
        
        $a_weight= (isset(self::$oauth_scope_settings[$a]['weight'])) ? self::$oauth_scope_settings[$a]['weight'] : 0;
        $b_weight = (isset(self::$oauth_scope_settings[$b]['weight'])) ? self::$oauth_scope_settings[$b]['weight'] : 0;
        
        if ($a_weight < $b_weight) return -1;
        if ($a_weight > $b_weight) return 1;
        
        return strcasecmp($a, $b);
    }

}
?>
