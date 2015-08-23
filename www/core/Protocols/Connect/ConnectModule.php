<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2012
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

namespace SimpleID\Protocols\Connect;

use Fernet\Fernet;
use Psr\Log\LogLevel;
use SimpleID\Auth\AuthManager;
use SimpleID\ModuleManager;
use SimpleID\Net\HTTPResponse;
use SimpleID\Protocols\OAuth\OAuthModule;
use SimpleID\Protocols\OAuth\OAuthProtectedResource;
use SimpleID\Protocols\OAuth\OAuthDynamicClient;
use SimpleID\Protocols\OAuth\Response;
use SimpleID\Store\StoreManager;
use SimpleJWT\Util\Helper;
use SimpleJWT\Crypt\Algorithm;
use SimpleJWT\Crypt\AlgorithmFactory;
use SimpleJWT\Keys\KeySet;
use \Web;

/**
 * Module for authenticating with OpenID Connect.
 */
class ConnectModule extends OAuthProtectedResource {

    static private $scope_settings = NULL;

    static function routes($f3) {
        $f3->route('GET /.well-known/openid-configuration', 'SimpleID\Protocols\Connect\ConnectModule->openid_configuration');
        $f3->route('GET|POST @connect_userinfo: /connect/userinfo', 'SimpleID\Protocols\Connect\ConnectModule->userinfo');
        $f3->route('GET @connect_jwks: /connect/jwks', 'SimpleID\Protocols\Connect\ConnectModule->jwks');
    }


    public function __construct() {
        parent::__construct();
        
        $mgr = ModuleManager::instance();
        $mgr->loadModule('SimpleID\Protocols\OAuth\OAuthModule');

        $this->checkConfig();
    }

    protected function checkConfig() {
        $config = $this->f3->get('config');

        if (!is_readable($config['public_jwks_file'])) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'Public JSON web key file not found.');
            $this->f3->error(500, $this->t('Public JSON web key file not found.  See the <a href="!url">manual</a> for instructions on how to set up OpenID Connect on SimpleID.', array('!url' => 'http://simpleid.koinic.net/docs/2/installing/#keys')));
        }

        if (!is_readable($config['private_jwks_file'])) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'Private JSON web key file not found.');
            $this->f3->error(500, $this->t('Private JSON web key file not found.  See the <a href="!url">manual</a> for instructions on how to set up OpenID Connect on SimpleID.', array('!url' => 'http://simpleid.koinic.net/docs/2/installing/#keys')));
        }
    }

    /**
     * @see SimpleID\API\OAuthHooks::oAuthResolveAuthRequestHook()
     */
    public function oAuthResolveAuthRequestHook($request, $response) {
        $store = StoreManager::instance();
        $web = Web::instance();

        // 1. Check if request_uri parameter is present.  If so, fetch the JWT
        // from this URL and place it in the request parameter
        if (isset($request['request_uri'])) {
            $this->logger->log(LogLevel::INFO, 'OpenID request object: getting object from ' . $request['request_uri']);
            
            $parts = parse_url($request['request_uri']);
            
            $http_response = new HTTPResponse($web->request($request['request_uri'], array('headers' => array('Accept' => 'application/jwt,text/plain,application/octet-stream'))));        

            if ($http_response->isHTTPError()) {
                $this->logger->log(LogLevel::ERROR, 'Cannot retrieve request file from request_uri:' . $request['request_uri']);
                $response->setError('invalid_request_uri', 'cannot retrieve request file from request_uri');
                return;
            }
            
            $request['request'] = $http_response->getBody();
            unset($request['request_uri']);
        }
        
        // 2. Check if the request parameter is present.  If so, we are dealing with
        // an additional OpenID Connect request object.  We need to parse this object
        if (isset($request['request'])) {
            $this->logger->log(LogLevel::INFO, 'OpenID request object token: ' . $request['request']);

            $client = $store->loadClient($request['client_id'], 'SimpleID\Protocols\OAuth\OAuthClient');

            if (!isset($client['connect']['request_object_signing_alg'])) {
                $this->logger->log(LogLevel::ERROR, 'Invalid OpenID request object: signature algorithm not registered');
                $response->setError('invalid_openid_request_object', 'signature algorithm not registered');
                return;
            }

            $jwt_alg = (isset($client['connect']['request_object_signing_alg'])) ? $client['connect']['request_object_signing_alg'] : null;
            $jwe_alg = (isset($client['connect']['request_object_encryption_alg'])) ? $client['connect']['request_object_encryption_alg'] : null;
            $builder = new KeySetBuilder($client);
            $set = $builder->addClientSecret()->addClientPublicKeys()->addServerPrivateKeys()->toKeySet();
            try {
                $helper = new Helper($request['request']);
                $jwt = $helper->getJWTObject($set, $jwe_alg, $jwt_alg);
                $request->loadData($jwt->getClaims());
            } catch (\UnexpectedValueException $e) {
                $this->logger->log(LogLevel::ERROR, 'Invalid OpenID request object: ' . $e->getMessage());
                $response->setError('invalid_openid_request_object', $e->getMessage());
                return;
            }
        }

        // 3. nonce
        if ($request->paramContains('scope', 'openid') && $request->paramContains('response_type', 'token') && !isset($request['nonce'])) {
            $this->logger->log(LogLevel::ERROR, 'Protocol Error: nonce not set when using implicit flow');
            $response->setError('invalid_request', 'nonce not set when using implicit flow')->renderRedirect();
            return;
        }
    }

    /**
     * @see SimpleID\API\OAuthHooks::oAuthProcessAuthRequestHook()
     */
    function oAuthProcessAuthRequestHook($request, $response) {
        $store = StoreManager::instance();
        $auth = AuthManager::instance();

        $client = $store->loadClient($request['client_id'], 'SimpleID\Protocols\OAuth\OAuthClient');

        // Check 1: Check whether the prompt parameter is present in the request
        $request->immediate = $request->paramContains('prompt', 'none');

        if ($request->paramContains('prompt', 'login')) {
            $this->f3->set('message', $this->t('This app\'s policy requires you to log in again to confirm your identity.'));
            return OAuthModule::CHECKID_REENTER_CREDENTIALS;
        }

        if ($request->paramContains('prompt', 'consent')) {
            return OAuthModule::CHECKID_APPROVAL_REQUIRED;
        }
        
        // Check 2: Check whether the max_age or acr parameters are present in the client defaults
        // or the request parameters
        if (isset($request['max_age'])) {
            $max_age = $request['max_age'];
        } elseif (isset($client['connect']) && isset($client['connect']['default_max_age'])) {
            $max_age = $client['connect']['default_max_age'];
        } else {
            $max_age = -1;
        }
        // If the relying party provides a max_auth_age
        if (($max_age > -1) && $auth->isLoggedIn()) {
            $auth_level = $auth->getAuthLevel();
            if ($auth_level == null) $auth_level = AuthManager::AUTH_LEVEL_SESSION;

            $auth_time = $auth->getAuthTime();
            if ($auth_time == null) $auth_time = 0;

            // If the last time we logged on actively (i.e. using a password) is greater than
            // max_age, we then require the user to log in again
            if (($auth_level <= AuthLevel::AUTH_LEVEL_CREDENTIALS) 
                || ((time() - $auth->getAuthTime()) > $max_age)) {
                $this->f3->set('message', $this->t('This web site\'s policy requires you to log in again to confirm your identity.'));
                return OAuthModule::CHECKID_REENTER_CREDENTIALS;
            }
        }

        if (isset($request['acr'])) {
            $acr = $request['acr'];
        } elseif (isset($client['connect']) && isset($client['connect']['default_acr'])) {
            $acr = $client['connect']['default_acr'];
        } else {
            $acr = -1;
        }

        if ($acr > -1) {
            return OAuthModule::CHECKID_INSUFFICIENT_TRUST;
        }

        return null;
    }


    /**
     * @see SimpleID\API\OAuthHooks::oAuthGrantAuthHook()
     */
    function oAuthGrantAuthHook($authorization, $request, $response, $scopes) {
        // code: ?code / id_token
        // id_token: #id_token
        // id_token token: #access_token #id_token
        // code id_token: #code #id_token[c_hash] / id_token
        // code token: #code #access_token / id_token
        // code id_token token: #code #access_token #id_token[c_hash, at_hash] / id_token

        if ($request->paramContains('scope', 'openid')) {
            $user = AuthManager::instance()->getUser();
            $client = StoreManager::instance()->loadClient($request['client_id'], 'SimpleID\Protocols\OAuth\OAuthClient');

            if (isset($request['claims']) && is_string($request['claims'])) $request['claims'] = json_decode($request['claims'], true);

            // 1. Build claims
            $claims_requested = (isset($request['claims']['id_token'])) ? $request['claims']['id_token'] : null;
            $claims = $this->buildClaims($user, $client, 'id_token', $scopes, $claims_requested);

            if (isset($request['nonce'])) $claims['nonce'] = $request['nonce'];

            // 2. Encode claims as jwt
            if ($request->paramContains('response_type', 'id_token')) {
                // response_type = id_token, code id_token, id_token token, code id_token token

                // Response is always fragment
                $response->setResponseMode(Response::FRAGMENT_RESPONSE_MODE);

                // Build authorisation response ID token
                $jose = new JOSEResponse($this->getCanonicalHost(), $client, 'connect.id_token', $claims, 'RS256');

                if (isset($response['code'])) $jose->setShortHashClaim('c_hash', $response['code']);
                if (isset($response['access_token'])) $jose->setShortHashClaim('at_hash', $response['access_token']);

                $response['id_token'] = $jose->buildJOSE();
            } 

            if ($request->paramContains('response_type', 'code')) {
                // response_type = code, code token

                // Save the id token for token endpoint
                $authorization->additional['id_token_claims'] = $claims;
            }
            // Note response_type = token is not defined

            // 3. Save claims for UserInfo endpoint
            if (isset($request['claims'])) {
                $authorization->additional['claims'] = $request['claims'];
            }
        }
    }

    function oAuthTokenHook($grant_type, $auth, $request, $response, $scopes) {
        if (($grant_type == 'authorization_code') && isset($auth->additional['id_token_claims'])) {
            $client = $this->oauth->getClient();
            $claims = $auth->additional['id_token_claims'];
            $access_token = $response['access_token'];
            
            // Build token response ID token
            $jose = new JOSEResponse($this->getCanonicalHost(), $client, 'connect.id_token', $claims, 'RS256');
            $jose->setShortHashClaim('at_hash', $access_token);

            $response['id_token'] = $jose->buildJOSE();
            unset($auth->additional['id_token_claims']);
        }
    }

    /** @see SimpleID\API\OAuthHooks::oAuthResponseTypesHook() */
    public function oAuthResponseTypesHook() {
        return array('id_token');
    }

    public function userinfo() {
        $this->checkHttps('error');

        $error = '';
        if (!$this->isTokenAuthorized('openid', $error)) {
            $this->unAuthorizedError($error);
        }

        $authorization = $this->getAuthorization();
        $user = $authorization->getOwner();
        $client = $authorization->getClient('SimpleID\Protocols\OAuth\OAuthClient');
        $scope = $this->getAccessToken()->getScope();

        $claims_requested = (isset($authorization->additional['claims']['userinfo'])) ? $authorization->additional['claims']['userinfo'] : null;
        $claims = $this->buildClaims($user, $client, 'userinfo', $scope, $claims_requested);
        if (count($claims) == 0) $this->unAuthorizedError('invalid_request');

        $response = new JOSEResponse($this->getCanonicalHost(), $client, 'connect.userinfo', $claims);
        $response->render();
    }

    /**
     * Build a set of claims to be included in an ID token or UserInfo response
     *
     * @param SimpleID\Models\User $user the user about which the ID
     * token is created
     * @param SimpleID\Models\Client $client the client to which the
     * ID token will be sent
     * @param string $context the context, either `id_token` or `userinfo`
     * @param array $scopes the scope
     * @param array $claims_requested the claims requested in the request object,
     * or null if the request object is not present
     * @return array an array of claims
     */
    private function buildClaims($user, $client, $context, $scopes, $claims_requested = NULL) {
        $auth = AuthManager::instance();
        $mgr = ModuleManager::instance();
        $scope_settings = $mgr->invokeAll('scopes');

        $claims = array();

        $claims['sub'] = $this->getSubject($user, $client);

        if ($claims_requested != null) {
            foreach ($claims_requested as $claim => $properties) {
                switch ($claim) {
                    case 'acr':
                        // Not allowed
                        break;
                    case 'updated_at':
                        // Not supported
                        break;
                    default:
                        $consent_scope = null;
                        foreach (array_keys($scope_settings['oauth']) as $scope => $settings) {
                            if (!isset($settings['claims'])) continue;
                            if (in_array($claim, $settings['claims'])) $consent_scope = $scope;
                        }
                        if ($consent_scope == null) continue; // No consent given for this claim

                        if (isset($user['userinfo'][$claim])) {
                            $claims[$claim] = $user['userinfo'][$claim];
                            if ($claim == 'email') $claims['email_verified'] = false;
                            if ($claim == 'phone_number') $claims['phone_number_verified'] = false;
                        }
                        break;
                }
            }
        } else {
            foreach (array('profile', 'email', 'address', 'phone') as $scope) {
                if (in_array($scope, $scopes)) {
                    if (isset($scope_settings['oauth'][$scope]['claims'])) {
                        foreach ($scope_settings['oauth'][$scope]['claims'] as $claim) {
                            if (isset($user['userinfo'][$claim])) $claims[$claim] = $user['userinfo'][$claim];
                            if ($claim == 'email') $claims['email_verified'] = false;
                            if ($claim == 'phone_number') $claims['phone_number_verified'] = false;
                        }
                    }
                }
            }
        }

        if ($context == 'id_token') {
            $now = time();
            $claims['exp'] = $now + SIMPLEID_LONG_TOKEN_EXPIRES_IN - SIMPLEID_LONG_TOKEN_EXPIRES_BUFFER;
            $claims['iat'] = $now;            
            $claims['azp'] = $client->getStoreID();
            $claims['auth_time'] = $auth->getAuthTime();
        }

        $hook_claims = $mgr->invokeAll('connectBuildClaims', $user, $client, $context, $scopes, $claims_requested);

        return array_merge($claims, $hook_claims);
    }

    /**
     * Obtains a `sub` (subject) claim for a user and client.
     *
     * The subject type can be public (which reflect the user's ID)
     * or pairwise.  The type chosen is dependent on the client's
     * registration settings.
     *
     * @param SimpleID\Models\User $user the user about which the ID
     * token is created
     * @param SimpleID\Models\Client $client the client to which the
     * ID token will be sent
     * @return string the subject
     */
    protected function getSubject($user, $client) {
        if (isset($client['connect']['sector_identifier_uri'])) {
            $sector_id = parse_url($client['connect']['sector_identifier_uri'], PHP_URL_HOST);
        } elseif (is_string($client['oauth']['redirect_uris'])) {
            $sector_id = parse_url($client['oauth']['redirect_uris'], PHP_URL_HOST);
        } elseif (is_array($client['oauth']['redirect_uris']) && (count($client['oauth']['redirect_uris']) == 1)) {
            $sector_id = parse_url($client['oauth']['redirect_uris'][0], PHP_URL_HOST);
        } else {
            $sector_id = $client->getStoreID();
        }

        $claims = array();

        $subject_type = (isset($client['connect']['subject_type'])) ? $client['connect']['subject_type'] : 'pairwise';
        switch ($subject_type) {
            case 'public':
                return $user->getStoreID();
                break;
            case 'pairwise':
                return $user->getPairwiseIdentity($sector_id);
                break;
            default:
                return null;
                break;
        }
    }

    /**
     * Returns the OpenID Connect scopes supported by this server.
     *
     * @see SimpleID\API\OAuthHooks::scopesHook()
     */
    public function scopesHook() {
        if (self::$scope_settings == NULL) {
            self::$scope_settings = array(
                'oauth' => array(
                    'openid' => array(
                        'description' => $this->t('know who you are'),
                        'weight' => -1
                    ),
                    'profile' => array(
                        'description' => $this->t('view your profile information (excluding e-mail and address information)'),
                        'claims' => array('name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale')
                    ),
                    'email' => array(
                        'description' => $this->t('view your e-mail address'),
                        'claims' => array('email')
                    ),
                    'address' => array(
                        'description' => $this->t('view your address information'),
                        'claims' => array('address')
                    ),
                    'phone' => array(
                        'description' => $this->t('view your phone number'),
                        'claims' => array('phone_number')
                    )
                )
            );
        }
        return self::$scope_settings;
    }


    /**
     * Displays the OpenID Connect configuration file for this installation.
     *
     */
    public function openid_configuration() {
        $mgr = ModuleManager::instance();

        header('Content-Type: application/json');
        header('Content-Disposition: inline; filename=openid-configuration');

        $scopes = $mgr->invokeAll('scopes');

        $jwt_signing_algs = AlgorithmFactory::getSupportedAlgs(Algorithm::SIGNATURE_ALGORITHM);
        $jwt_encryption_algs = AlgorithmFactory::getSupportedAlgs(Algorithm::KEY_ALGORITHM);
        $jwt_encryption_enc_algs = AlgorithmFactory::getSupportedAlgs(Algorithm::ENCRYPTION_ALGORITHM);

        $claims_supported = array('sub', 'iss', 'auth_time', 'acr');
        foreach ($scopes['oauth'] as $scope => $settings) {
            if (isset($settings['claims'])) {
                $claims_supporteds = array_merge($claims_supported, $settings['claims']);
            }
        }

        $token_endpoint_auth_methods_supported = array('client_secret_basic', 'client_secret_post');
        
        $config = array(
            'issuer' => $this->getCanonicalHost(),
            'authorization_endpoint' => $this->getCanonicalURL('@oauth_auth', '', 'https'),
            'token_endpoint' => $this->getCanonicalURL('@oauth_token', '', 'https'),
            'userinfo_endpoint' => $this->getCanonicalURL('@connect_userinfo', '', 'https'),
            'jwks_uri' => $this->getCanonicalURL('@connect_jwks', '', 'https'),
            'scopes_supported' => array_keys($scopes['oauth']),
            'response_types_supported' => array('code', 'token', 'id_token', 'id_token token', 'code token', 'code id_token', 'code id_token token'),
            'response_modes_supported' => Response::getResponseModesSupported(),
            'grant_types_supported' => array('authorization_code', 'refresh_token'),
            'acr_values_supported' => array(),
            'subject_types_supported' => array('public', 'pairwise'),
            'userinfo_signing_alg_values_supported' => $jwt_signing_algs,
            'userinfo_encryption_alg_values_supported' => $jwt_encryption_algs,
            'userinfo_encryption_enc_alg_values_supported' => $jwt_encryption_enc_algs,
            'id_token_signing_alg_values_supported' => $jwt_signing_algs,
            'id_token_encrpytion_alg_values_supported' => $jwt_encryption_algs,
            'id_token_encrpytion_enc_alg_values_supported' => $jwt_encryption_enc_algs,
            'request_object_signing_alg_values_supported' => $jwt_signing_algs,
            'request_object_encryption_alg_values_supported' => $jwt_encryption_algs,
            'request_object_encryption_enc_alg_values_supported' => $jwt_encryption_enc_algs,
            'token_endpoint_auth_methods_supported' => $token_endpoint_auth_methods_supported,
            'claim_types_supported' => array('normal'),
            'claims_supported' => $claims_supported,
            'claims_parameter_supported' => true,
            'request_parameter_supported' => true,
            'request_uri_parameter_supported' => true,
            'require_request_uri_registration' => false,
            'service_documentation' => 'http://simpleid.koinic.net/docs/'
        );
        
        $config = array_merge($config, $mgr->invokeAll('connectConfiguration'));
        print json_encode($config);
    }


    /**
     * Displays the JSON web key for this installation.
     */
    public function jwks() {
        $config = $this->f3->get('config');

        if (!isset($config['public_jwks_file'])) {
            $this->f3->status(404);
            $this->fatalError($this->t('No web key file found.'));
        }
        
        $set = new KeySet();
        $set->load(file_get_contents($config['public_jwks_file']));

        if (!$set->isPublic()) {
            $this->f3->status(401);
            $this->fatalError($this->t('Web key file not public.'));
        }

        header('Content-Type: application/jwk-set+json');
        header('Content-Disposition: inline; filename=jwks.json');
        print $set->toJWKS();
    }

    /**
     * Obtains the SimpleID host URL.
     *
     * @param string $secure if $relative is false, either 'https' to force an HTTPS connection, 'http' to force
     * an unencrypted HTTP connection, 'detect' to base on the current connection, or NULL to vary based on SIMPLEID_BASE_URL
     * @return string the url
     *
     */
    public function getCanonicalHost($secure = null) {
        $config = $this->f3->get('config');
        $canonical_base_path = $config['canonical_base_path'];

        $parts = parse_url($canonical_base_path);
        
        if ($secure == 'https') {
            $scheme = 'https';
        } elseif ($secure == 'http') {
            $scheme = 'http';
        } else {
            $scheme = $parts['scheme'];
        }
        
        $url = $scheme . '://';
        if (isset($parts['user'])) {
            $url .= $parts['user'];
            if (isset($parts['pass'])) $url .= ':' . $parts['pass'];
            $url .= '@';
        }
        $url .= $parts['host'];
        if (isset($parts['port'])) $url .= ':' . $parts['port'];

        return $url;
    }
}
?>
