<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2025
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
use SimpleID\Base\ScopeInfoCollectionEvent;
use SimpleID\Base\ConsentEvent;
use SimpleID\Base\RequestState;
use SimpleID\Protocols\ProtocolResult;
use SimpleID\Protocols\ProtocolResultEvent;
use SimpleID\Store\StoreManager;
use SimpleID\Util\SecurityToken;
use SimpleID\Util\Events\GenericStoppableEvent;
use SimpleID\Util\Events\BaseDataCollectionEvent;
use SimpleID\Util\Forms\FormState;
use SimpleID\Util\Forms\FormBuildEvent;
use SimpleID\Util\Forms\FormSubmitEvent;
use SimpleID\Util\UI\Template;

/**
 * The module for authentication using OAuth.
 *
 * This module contains basic functions for process authorisation
 * requests and granting access tokens.
 */
class OAuthModule extends Module implements ProtocolResult {

    const DEFAULT_SCOPE = 'tag:simpleid.sf.net,2014:oauth:default';

    /** @var array<string, mixed>|null */
    static private $oauth_scope_settings = NULL;

    /** @var OAuthManager */
    protected $oauth;

    /** @var ModuleManager */
    protected $mgr;

    static function init($f3) {
        $f3->route('GET @oauth_auth: /oauth/auth', 'SimpleID\Protocols\OAuth\OAuthModule->auth');
        $f3->route('POST @oauth_token: /oauth/token', 'SimpleID\Protocols\OAuth\OAuthModule->token');
        $f3->route('POST @oauth_consent: /oauth/consent', 'SimpleID\Protocols\OAuth\OAuthModule->consent');
        $f3->route('POST @oauth_revoke: /oauth/revoke', 'SimpleID\Protocols\OAuth\OAuthModule->revoke');
        $f3->route('POST @oauth_introspect: /oauth/introspect', 'SimpleID\Protocols\OAuth\OAuthModule->introspect');
        $f3->route('GET @oauth_metadata: /.well-known/oauth-authorization-server', 'SimpleID\Protocols\OAuth\OAuthModule->metadata');
    }

    public function __construct() {
        parent::__construct();
        $this->oauth = OAuthManager::instance();
        $this->mgr = ModuleManager::instance();
    }

    /**
     * Run post-initialisation procedures.  This event is only called in the main
     * SimpleID invocation, and not during the upgrade process.
     *
     * @return void
     */
    public function onPostInit(GenericStoppableEvent $event) {
        $event = new ScopeInfoCollectionEvent();
        \Events::instance()->dispatch($event);
        
        self::$oauth_scope_settings = $event->getScopeInfoForType('oauth');
    }

    /**
     * Prepares an OAuth authorisation request for processing.
     *
     * This function checks the request for protocol compliance via
     * {@link checkAuthRequest()} before passing it to {@link processAuthRequest()} 
     * for processing.
     * 
     * @return void
     * @see checkAuthRequest()
     * @see processAuthRequest()
     * @since 2.0
     */
    public function auth() {
        $this->checkHttps('redirect');

        $dispatcher = \Events::instance();

        $request = new Request($this->f3->get('GET'), []);
        
        $this->logger->log(LogLevel::INFO, 'OAuth authorisation request: ', $request->toArray());
        
        $response = new Response($request);

        $resolve_event = new OAuthEvent($request, $response, 'oauth_auth_resolve');
        $dispatcher->dispatch($resolve_event);
        if ($response->isError()) {
            if (isset($request['redirect_uri'])) {
                $response->renderRedirect();
            } else {
                $this->fatalError($this->f3->get('intl.common.protocol_error', $response['error']), 400);
            }
            return;
        }
        
        $this->checkAuthRequest($request, $response);

        $resolve_event = new OAuthEvent($request, $response, 'oauth_auth_check');
        $dispatcher->dispatch($resolve_event);
        if ($response->isError()) {
            if (isset($request['redirect_uri'])) {
                $response->renderRedirect();
            } else {
                $this->fatalError($this->f3->get('intl.common.protocol_error', $response['error']), 400);
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
     * @return void
     * @see processAuthRequest()
     */
    protected function checkAuthRequest($request, $response) {
        $store = StoreManager::instance();

        // 1. response_type (pass 1 - check that it exists)
        if (!isset($request['response_type'])) {
            $this->logger->log(LogLevel::ERROR, 'Protocol Error: response_type not set.');
            $this->fatalError($this->f3->get('intl.core.oauth.missing_response_type'), 400);
            return;
        }
        
        $response_types = preg_split('/\s+/', $request['response_type']);
        if ($response_types == false) {
            $this->logger->log(LogLevel::ERROR, 'Protocol Error: Incorrect response_type.');
            $this->fatalError($this->f3->get('intl.core.oauth.invalid_response_type'), 400);
            return;
        }
        if (in_array('token', $response_types)) $response->setResponseMode(Response::FRAGMENT_RESPONSE_MODE);

        // 2. client_id (pass 1 - check that it exists)
        if (!isset($request['client_id'])) {
            $this->logger->log(LogLevel::ERROR, 'Protocol Error: client_id not set');
            if (isset($request['redirect_uri'])) {
                $response->setError('invalid_request', 'client_id not set')->renderRedirect();
            } else {
                $this->fatalError($this->f3->get('intl.core.oauth.missing_client_id'), 400);
            }
            return;
        }
        
        /** @var \SimpleID\Protocols\OAuth\OAuthClient $client */
        $client = $store->loadClient($request['client_id'], 'SimpleID\Protocols\OAuth\OAuthClient');
        if ($client == NULL) {
            $this->logger->log(LogLevel::ERROR, 'Client with client_id not found: ' . $request['client_id']);
            if (isset($request['redirect_uri'])) {
                $response->setError('invalid_request', 'client not found')->renderRedirect();
            } else {
                $this->fatalError($this->f3->get('intl.core.oauth.client_not_found'), 400);
            }
            return;
        }
        
        // 3. redirect_uri
        if (isset($request['redirect_uri'])) {
            // Validate against client registration for public clients and implicit grant types
            if (!$client->hasRedirectUri($request['redirect_uri'])) {
                $this->logger->log(LogLevel::ERROR, 'Incorrect redirect URI: ' . $request['redirect_uri']);
                $this->fatalError($this->f3->get('intl.core.oauth.invalid_redirect_uri'), 400);
                return;
            }
        } elseif (isset($client['oauth']['redirect_uris'])) {
            if (is_string($client['oauth']['redirect_uris'])) {
                $response->setRedirectURI($client['oauth']['redirect_uris']);
            } elseif (count($client['oauth']['redirect_uris']) == 1) {
                $response->setRedirectURI($client['oauth']['redirect_uris'][0]);
            } else {
                $this->logger->log(LogLevel::ERROR, 'Protocol Error: redirect_uri not specified in request when multiple redirect_uris are registered');
                $this->fatalError($this->f3->get('intl.core.oauth.ambiguous_redirect_uri'), 400);
                return;
            }
        } else {
            $this->logger->log(LogLevel::ERROR, 'Protocol Error: redirect_uri not specified in request or client registration');
            $this->fatalError($this->f3->get('intl.core.oauth.missing_redirect_uri'), 400);
            return;
        }
        
        // 4. response_type (pass 2 - check that all are supported)
        $event = new BaseDataCollectionEvent('oauth_response_types');
        \Events::instance()->dispatch($event);

        $supported_response_types = $event->getResults();
        foreach ($response_types as $response_type) {
            if (!in_array($response_type, $supported_response_types)) {
                $this->logger->log(LogLevel::ERROR, 'Protocol Error: unsupported response_type: ' . $response_type);
                $response->setError('unsupported_response_type', 'unsupported response_type: ' . $response_type)->renderRedirect();
                return;
            }
        }

        // 5. PKCE required for native clients - RFC 8252 section 8.1
        if ($client->isNative() && $request->paramContains('response_type', 'code') && !isset($request['code_challenge'])) {
            $this->logger->log(LogLevel::ERROR, 'Protocol Error: code_challenge required for native apps');
            $response->setError('invalid_request', 'code_challenge required for native apps')->renderRedirect();
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
     * @return void
     * @see checkAuthRequest()
     */
    protected function processAuthRequest($request, $response) {
        $this->logger->log(LogLevel::INFO, 'Expanded OAuth authorisation request: ', $request->toArray());

        $core_result = $this->checkIdentity($request);

        $event = new OAuthAuthRequestEvent($request, $response);
        $event->setResult($core_result);
        \Events::instance()->dispatch($event);
        $result = $event->getResult();
        
        switch ($result) {
            case self::CHECKID_OK:
                $this->logger->log(LogLevel::INFO, 'CHECKID_OK');
                
                if (isset($request['scope'])) {
                    $scopes = $request->paramToArray('scope');
                } else {
                    $scopes = [ self::DEFAULT_SCOPE ];
                }
                $this->grantAuth($request, $response, $scopes);
                break;
            case self::CHECKID_APPROVAL_REQUIRED:
                $this->logger->log(LogLevel::INFO, 'CHECKID_APPROVAL_REQUIRED');
                if ($request->isImmediate()) {
                    $response->setError('consent_required', 'Consent required')->renderRedirect();
                } else {
                    $this->consentForm($request, $response);
                }
                break;
            case self::CHECKID_REENTER_CREDENTIALS:
            case self::CHECKID_LOGIN_REQUIRED:
                $this->logger->log(LogLevel::INFO, 'CHECKID_LOGIN_REQUIRED');
                if ($request->isImmediate()) {
                    $response->setError('login_required', 'Login required')->renderRedirect();
                } else {
                    $token = new SecurityToken();
                    $request_state = new RequestState();
                    $request_state->setRoute('/oauth/auth')->setParams($request->toArray());
                    $form_state = new FormState([
                        'mode' => AuthManager::MODE_CREDENTIALS,
                        'auth_skip_activity' => true
                    ]);
                    $form_state->setRequest($request);
                    if ($result == self::CHECKID_REENTER_CREDENTIALS) {
                        $auth = AuthManager::instance();
                        $user = $auth->getUser();
                        $form_state['uid'] = $user['uid'];
                        $form_state['mode'] = AuthManager::MODE_REENTER_CREDENTIALS;
                    }

                    /** @var \SimpleID\Auth\AuthModule $auth_module */
                    $auth_module = $this->mgr->getModule('SimpleID\Auth\AuthModule');
                    $auth_module->loginForm([
                        'destination' => 'continue/' . rawurlencode($token->generate($request_state))
                    ], $form_state);
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
            $scopes = [ self::DEFAULT_SCOPE ];
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
     * @param array<string>|null $scopes the requested scope
     * @return void
     */
    protected function grantAuth($request, $response, $scopes = NULL) {
        $dispatcher = \Events::instance();
        $store = StoreManager::instance();

        $user = AuthManager::instance()->getUser();
        $client = $store->loadClient($request['client_id'], 'SimpleID\Protocols\OAuth\OAuthClient');
        if ($scopes == NULL) {
            if (isset($request['scope'])) {
                $scopes = $request->paramToArray('scope');
            } else {
                $scopes = [ self::DEFAULT_SCOPE ];
            }
        }

        /** @var Authorization $authorization */
        $authorization = $store->loadAuth(Authorization::buildID($user, $client));

        if ($authorization == null) {
            $authorization = new Authorization($user, $client, $scopes);
        } else {
            $authorization->setScope($scopes);
        }

        $result_event = new ProtocolResultEvent(self::CHECKID_OK, $user, $client);
        $dispatcher->dispatch($result_event);

        if ($request->paramContains('response_type', 'code')) {
            $additional = [];
            if (isset($request['code_challenge'])) {
                $additional['code_challenge'] = $request['code_challenge'];
                $additional['code_challenge_method'] = (isset($request['code_challenge_method'])) ? $request['code_challenge_method'] : 'plain';
            }
            $response['code'] = $authorization->issueCode((isset($request['redirect_uri'])) ? $request['redirect_uri'] : NULL, NULL, $additional);
        }

        if ($request->paramContains('response_type', 'token')) {
            $response->loadData($authorization->issueAccessToken($scopes, SIMPLEID_SHORT_TOKEN_EXPIRES_IN));

            $token_event = new OAuthTokenGrantEvent('implicit', $authorization, $request, $response, $scopes);
            $dispatcher->dispatch($token_event);
        }

        $grant_auth_event = new OAuthAuthGrantEvent($authorization, $request, $response, $scopes);
        $dispatcher->dispatch($grant_auth_event);

        $store->saveAuth($authorization);
        $store->saveUser($user);

        $this->logger->log(LogLevel::DEBUG, 'Authorization granted: ', $response->toArray());

        $response->renderRedirect();
    }

    /**
     * Processes an OAuth token request.
     * 
     * @return void
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
        
        $this->oauth->initClient();
        $client = $this->oauth->getClient();

        if (!$this->oauth->isClientAuthenticated(true, isset($client['oauth']['token_endpoint_auth_method']) ? $client['oauth']['token_endpoint_auth_method'] : null)) {
            $this->logger->log(LogLevel::ERROR, 'Client authentication failed');
            $response->setError('invalid_client', 'client authentication failed');
            $response->renderJSON();
            return;
        }

        $grant_types = (isset($client['oauth']['grant_types'])) ? $client['oauth']['grant_types'] : [ 'authorization_code' ];
        if (!in_array($request['grant_type'], $grant_types)) {
            $this->logger->log(LogLevel::ERROR, 'Grant type not registered by client');
            $response->setError('unauthorized_client', 'Grant type not registered by client');
            $response->renderJSON();
            return;
        }
        
        switch ($request['grant_type']) {
            case 'authorization_code':
                $this->tokenFromCode($request, $response);
                break;
            case 'refresh_token':
                $this->tokenFromRefreshToken($request, $response);
                break;
            case 'password':
            case 'client_credentials':
                // Not allowed
            default:
                // Extensions can be put here.
                $this->logger->log(LogLevel::ERROR, 'Token request failed: unsupported grant type');
                $response->setError('unsupported_grant_type', 'grant type ' . $request['grant_type'] . ' is not supported');
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
     * @return void
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
        $authorization->revokeTokensFromGrant($code);
        

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

        // 5. PKCE
        $additional = $code->getAdditional();
        if (isset($additional['code_challenge'])) {
            if (!isset($request['code_verifier'])) {
                $this->logger->log(LogLevel::ERROR, 'Token request failed: code_verifier not found');
                $response->setError('invalid_grant', 'code_verifier not found');
                return;
            }

            $code_verified = false;
            switch ($additional['code_challenge_method']) {
                case 'plain':
                    $test_code_challenge = $request['code_verifier'];
                    break;
                case 'S256':
                    $test_code_challenge = trim(strtr(base64_encode(hash('sha256', $request['code_verifier'], true)), '+/', '-_'), '=');
                    break;
                default:
                    $this->logger->log(LogLevel::ERROR, 'Token request failed: unknown code_challenge_method: ' . $additional['code_challenge_method']);
                    $response->setError('invalid_grant', 'unknown code_challenge_method');
                    return;
            }
            $code_verified = $this->secureCompare($test_code_challenge, $additional['code_challenge']);
            if (!$code_verified) {
                $this->logger->log(LogLevel::ERROR, 'Token request failed: code_challenge in request <' . $test_code_challenge . '> does not match stored code_challenge <' . $additional['code_challenge'] . '>');
                $response->setError('invalid_grant', 'code_verifier does not match');
                return;
            }
        }

        $scope = $code->getScope();

        // If we issue, we delete the code so that it can't be used again
        $code->clear();

        $response->loadData($authorization->issueTokens($scope, SIMPLEID_SHORT_TOKEN_EXPIRES_IN, $code));

        // Call modules
        $event = new OAuthTokenGrantEvent('authorization_code', $authorization, $request, $response, $scope);
        \Events::instance()->dispatch($event);
    }

    /**
     * Processes an OAuth refresh token request.
     *
     * @param Request $request the OAuth token request
     * @param Response $response the response
     * @return void
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
            return;
        }
        $authorization->revokeTokensFromGrant($refresh_token);
        
        $scope = $refresh_token->getScope();

        // If we issue, we delete the old refresh token so that it can't be used again
        $refresh_token->revoke();
        $authorization->resetAuthState();
        $store->saveAuth($authorization);

        $response->loadData($authorization->issueTokens($scope, SIMPLEID_SHORT_TOKEN_EXPIRES_IN, $refresh_token));

        // Call modules
        $event = new OAuthTokenGrantEvent('refresh_token', $authorization, $request, $response, $scope);
        \Events::instance()->dispatch($event);
    }


    /**
     * Provides a form for user authorisation of an OAuth client.
     *
     * @param Request $request the OAuth request
     * @param Response $response the OAuth response
     * @return void
     * @since 2.0
     */
    protected function consentForm($request, $response) {
        $store = StoreManager::instance();
        $tpl = Template::instance();

        $client = $store->loadClient($request['client_id'], 'SimpleID\Protocols\OAuth\OAuthClient');

        $form_state = new FormState();
        $form_state->setRequest($request);
        $form_state->setResponse($response);

        $request_state = new RequestState();
        $request_state->setParams($request->toArray());
        
        $application_name = $client->getDisplayName();
        $application_type = (isset($client['oauth']['application_type'])) ? $client['oauth']['application_type'] : '';
        
        $this->f3->set('application_name', $application_name);
        $this->f3->set('application_type', $application_type);
        
        if (isset($client['logo_url'])) {
            $this->f3->set('logo_url', $client['logo_url']);
        }
        
        if (isset($request['scope'])) {
            $scopes = $request->paramToArray('scope');
        } else {
            $scopes = [ self::DEFAULT_SCOPE ];
        }
        usort($scopes, [ $this, 'sortScopes' ]);
        
        $scope_list = [];
        foreach ($scopes as $scope) {
            $scope_list[$scope] = (isset(self::$oauth_scope_settings[$scope]['description'])) ? self::$oauth_scope_settings[$scope]['description'] : 'scope ' . $scope;
        }
        $this->f3->set('scope_list', $scope_list);

        if ($client->isDynamic()) {
            $this->f3->set('client_dynamic', 'client-dynamic');
        }

        $client_info = [];
        if (isset($client['oauth']['website'])) {
            $client_info[] = $this->f3->get('intl.common.consent.website', $client['oauth']['website']);
        }
        if (isset($client['oauth']['policy_url'])) {
            $client_info[] = $this->f3->get('intl.common.consent.policy_url', $client['oauth']['policy_url']);
        }
        if (isset($client['oauth']['tos_url'])) {
            $client_info[] = $this->f3->get('intl.common.consent.tos_url', $client['oauth']['tos_url']);
        }
        if (isset($client['oauth']['contacts'])) {
            $contacts = [];
            
            if (is_array($client['oauth']['contacts'])) {
                foreach ($client['oauth']['contacts'] as $contact) {
                    $contacts[] = '<a href="mailto:' . $this->rfc3986_urlencode($contact) . '">' . $this->f3->clean($contact) . '</a>';
                }
            } else {
                $contacts[] = '<a href="mailto:' . $this->rfc3986_urlencode($client['oauth']['contacts']) . '">' . $this->f3->clean($client['oauth']['contacts']) . '</a>';
            }
            
            $client_info[] = $this->f3->get('intl.common.consent.contacts', implode(', ', $contacts));
        }
        $this->f3->set('client_info', $client_info);
        
        $token = new SecurityToken();
        $this->f3->set('tk', $token->generate('oauth_consent', SecurityToken::OPTION_BIND_SESSION));
        $this->f3->set('fs', $token->generate($form_state->encode()));

        $this->f3->set('logout_destination', '/continue/' . rawurlencode($token->generate($request_state)));
        $this->f3->set('user_header', true);
        $this->f3->set('title', $this->f3->get('intl.core.oauth.oauth_title'));
        $this->f3->set('page_class', 'is-dialog-page');
        $this->f3->set('layout', 'oauth_consent.html');

        $event = new FormBuildEvent($form_state, 'oauth_consent_form_build');
        \Events::instance()->dispatch($event);
        $tpl->mergeAttachments($event);
        $this->f3->set('forms', $event->getBlocks());
        
        header('X-Frame-Options: DENY');
        print $tpl->render('page.html');
    }


    /**
     * Processes a user response from the {@link consentForm()} function.
     *
     * @return void
     * @since 2.0
     */
    function consent() {
        $auth = AuthManager::instance();
        $token = new SecurityToken();
        $store = StoreManager::instance();
    
        if (!$auth->isLoggedIn()) {
            /** @var \SimpleID\Auth\AuthModule $auth_module */
            $auth_module = $this->mgr->getModule('SimpleID\Auth\AuthModule');
            $auth_module->loginForm();
            return;
        }
        $user = $auth->getUser();
        
        $form_state = FormState::decode($token->getPayload($this->f3->get('POST.fs')), Request::class, Response::class);
        /** @var Request $request */
        $request = $form_state->getRequest();
        /** @var Response $response */
        $response = $form_state->getResponse();

        if (!$token->verify($this->f3->get('POST.tk'), 'oauth_consent')) {
            $this->logger->log(LogLevel::WARNING, 'Security token ' . $this->f3->get('POST.tk') . ' invalid.');
            $this->f3->set('message', $this->f3->get('intl.common.invalid_tk'));
            $this->consentForm($request, $response);
            return;
        }
        
        if ($this->f3->get('POST.op') == 'deny') {
            $response->setError('access_denied')->renderRedirect();
            return;
        } else {
            $event = new FormSubmitEvent($form_state, 'oauth_consent_form_submit');
            \Events::instance()->dispatch($event);

            $client = $store->loadClient($request['client_id'], 'SimpleID\Protocols\OAuth\OAuthClient');
            $cid = $client->getStoreID();
            $now = time();

            $consents = [ 'oauth' => $this->f3->get('POST.prefs.consents.oauth') ];

            if (isset($user->clients[$cid])) {
                $prefs = $user->clients[$cid];
            } else {
                $prefs = [
                    'oauth' => [],
                    'store_id' => $client->getStoreID(),
                    'display_name' => $client->getDisplayName(),
                    'display_html' => $client->getDisplayHTML(),
                    'first_time' => $now,
                    'consents' => [],
                ];
            }

            $prefs['last_time'] = $now;
            $prefs['consents'] = array_merge($prefs['consents'], $consents);

            if ($this->f3->exists('POST.prefs.oauth.prompt_none') && ($this->f3->get('POST.prefs.oauth.prompt_none') == 'true')) {
                $prefs['oauth']['prompt_none'] = true;
            }
                
            $user->clients[$cid] = $prefs;
            $store->saveUser($user);
        }

        $this->processAuthRequest($request, $response);
    }

    /**
     * Endpoint for token revocation requests
     * 
     * @link https://datatracker.ietf.org/doc/html/rfc7009
     * @return void
     */
    public function revoke() {
        $request = new Request($this->f3->get('POST'));
        $response = new Response($request);
        
        $this->checkHttps('error');
        
        $this->logger->log(LogLevel::INFO, 'OAuth token revocation request: ', $request->toArray());
                
        $this->oauth->initClient();
        $client = $this->oauth->getClient();

        if (!$this->oauth->isClientAuthenticated(true, isset($client['oauth']['token_endpoint_auth_method']) ? $client['oauth']['token_endpoint_auth_method'] : null)) {
            $this->logger->log(LogLevel::ERROR, 'Client authentication failed');
            $response->setError('invalid_client', 'client authentication failed');
            $response->renderJSON();
            return;
        }

        $token = $this->inferTokenFromRequestBody($request, $response);
        if ($response->isError()) {
            $response->renderJSON();
            return;
        }

        if (($token != null) && $token->isValid()) {
            $authorization = $token->getAuthorization();
            if ($authorization->getClient()->getStoreID() != $client->getStoreID()) {
                $this->logger->log(LogLevel::ERROR, 'Token revocation request failed: this client (' . $client->getStoreID() . ') does not match the client stored in token (' . $authorization->getClient()->getStoreID() . ')');
                $response->setError('invalid_grant', 'this client does not match the client stored in token');
                $response->renderJSON();
                return;
            }

            $token->revoke();
        }

        // It does not matter what we put here, as the client is supposed to ignore
        // the response body.
        $response['success'] = true;
        $response->renderJSON();
    }

    /**
     * Endpoint for token revocation requests
     * 
     * @link https://datatracker.ietf.org/doc/html/rfc7009
     * @return void
     */
    public function introspect() {
        $request = new Request($this->f3->get('POST'));
        $response = new Response($request);
        
        $this->checkHttps('error');
        
        $this->logger->log(LogLevel::INFO, 'OAuth token revocation request: ', $request->toArray());
                
        $this->oauth->initClient();
        $client = $this->oauth->getClient();

        if (!$this->oauth->isClientAuthenticated(true, isset($client['oauth']['token_endpoint_auth_method']) ? $client['oauth']['token_endpoint_auth_method'] : null)) {
            $this->logger->log(LogLevel::ERROR, 'Client authentication failed');
            $response->setError('invalid_client', 'client authentication failed');
            $response->renderJSON();
            return;
        }

        $token = $this->inferTokenFromRequestBody($request, $response);
        if ($response->isError()) {
            $response->renderJSON();
            return;
        }

        if (($token == null) || (!$token->isValid())) {
            $response['active'] = false;
            $response->renderJSON();
            return;
        }

        $authorization = $token->getAuthorization();
        if ($authorization->getClient()->getStoreID() != $client->getStoreID()) {
            $this->logger->log(LogLevel::ERROR, 'Token introspection request failed: this client (' . $client->getStoreID() . ') does not match the client stored in token (' . $authorization->getClient()->getStoreID() . ')');
            $response->setError('invalid_grant', 'this client does not match the client stored in token');
            $response->renderJSON();
            return;
        }

        $expiry = $token->getExpiry();

        $response['active'] = true;
        $response['scope'] = implode(' ', $token->getScope());
        $response['client_id'] = $client->getStoreID();
        $response['token_type'] = $token->getType();
        if ($expiry != null) $response['exp'] = $expiry;

        $response->renderJSON();
    }

    /**
     * Displays the OAuth authorisation server metadata for this installation.
     *
     * @link https://datatracker.ietf.org/doc/html/rfc8414
     * @return void
     */
    public function metadata() {
        $dispatcher = \Events::instance();

        header('Content-Type: application/json');
        header('Content-Disposition: inline; filename=oauth-authorization-server');

        $scope_info_event = new ScopeInfoCollectionEvent();
        $dispatcher->dispatch($scope_info_event);
        $scopes = $scope_info_event->getScopeInfoForType('oauth');

        $config = [
            'issuer' => $this->getCanonicalHost(),
            'authorization_endpoint' => $this->getCanonicalURL('@oauth_auth', '', 'https'),
            'token_endpoint' => $this->getCanonicalURL('@oauth_token', '', 'https'),
            'revocation_endpoint' => $this->getCanonicalURL('@oauth_revoke', '', 'https'),
            'introspection_endpoint' => $this->getCanonicalURL('@oauth_introspect', '', 'https'),
            'scopes_supported' => array_keys($scopes),
            'response_types_supported' => [ 'code', 'token', 'code token' ],
            'response_modes_supported' => Response::getResponseModesSupported(),
            'grant_types_supported' => [ 'authorization_code', 'refresh_token' ],
            'token_endpoint_auth_methods_supported' => $this->oauth->getSupportedClientAuthMethods(),
            'revocation_endpoint_auth_methods_supported' => $this->oauth->getSupportedClientAuthMethods(),
            'introspection_endpoint_auth_methods_supported' => $this->oauth->getSupportedClientAuthMethods(),
            'code_challenge_methods_supported' => [ 'plain', 'S256' ],
            'service_documentation' => 'https://simpleid.org/docs/'
        ];

        $config_event = new BaseDataCollectionEvent('oauth_metadata', BaseDataCollectionEvent::MERGE_RECURSIVE);
        $config_event->addResult($config);
        $dispatcher->dispatch($config_event);
        print json_encode($config_event->getResults());
    }

    /**
     * @see SimpleID\Base\ScopeInfoCollectionEvent
     * @return void
     */
    public function onScopeInfoCollectionEvent(ScopeInfoCollectionEvent $event) {
        $event->addScopeInfo('oauth', [
            self::DEFAULT_SCOPE => [
                'description' => $this->f3->get('intl.common.scope.id'),
                //'required' => true
            ]
        ]);
    }

    /**
     * @return void
     */
    public function onOauthResponseTypes(BaseDataCollectionEvent $event) {
        $event->addResult([ 'token', 'code' ]);
    }

    /** 
     * @see SimpleID\API\MyHooks::revokeAppHook()
     * @return void
     */
    public function onConsentRevoke(ConsentEvent $event) {
        $cid = $event->getConsentID();
        $auth = AuthManager::instance();
        $store = StoreManager::instance();
        
        $user = $auth->getUser();
        $client = $store->loadClient($cid, 'SimpleID\Protocols\OAuth\OAuthClient');

        $aid = Authorization::buildID($user, $client);

        /** @var Authorization $authorization */
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
    protected function rfc3986_urlencode($s) {
        return str_replace('%7E', '~', rawurlencode($s));
    }

    /**
     * Infers a token by parsing the `token` and `token_type_hint` parameters
     * in the body of a request.  If `token_type_hint` exists, then the
     * appropriate `Token` object is created from `token`.  If `token_type_hint`
     * does not exist, it firstly attempts to create an access token, then
     * it attempts to create a refresh token.
     * 
     * Note that the token returned may not be valid.
     * 
     * If an error occurs, then an appropriate error response is set using
     * the supplied response object
     * 
     * @param Request $request the request
     * @param Response $response the response
     * @return ?Token the access or refresh token, or null if no token can be found
     */
    protected function inferTokenFromRequestBody(Request $request, Response $response): ?Token {
        if (!isset($request['token']) || ($request['token'] == '')) {
            $this->logger->log(LogLevel::ERROR, 'Token operation request failed: token not set');
            $response->setError('invalid_request', 'token not set');
            return null;
        }

        if (isset($request['token_type_hint'])) {
            switch ($request['token_type_hint']) {
                case 'access_token':
                    $token = AccessToken::decode($request['token']);
                    break;
                case 'refresh_token':
                    $token = RefreshToken::decode($request['token']);
                    break;
                default:
                    $this->logger->log(LogLevel::ERROR, 'Token operation request failed: unsupported token type');
                    $response->setError('unsupported_token_type', 'unsupported token type');
                    return null;
            }
        } else {
            // No token_type_hint. Try access_token, then refresh_token
            $token = AccessToken::decode($request['token']);
            if (!$token->isValid()) $token = RefreshToken::decode($request['token']);
            if (!$token->isValid()) $token = null;
        }

        return $token;
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
     * @param string $a
     * @param string $b
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
