<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2012-2022
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

use Psr\Log\LogLevel;
use SimpleID\ModuleManager;
use SimpleID\Auth\AuthManager;
use SimpleID\Base\ScopeInfoCollectionEvent;
use SimpleID\Protocols\HTTPResponse;
use SimpleID\Protocols\ProtocolResult;
use SimpleID\Protocols\OAuth\OAuthModule;
use SimpleID\Protocols\OAuth\OAuthEvent;
use SimpleID\Protocols\OAuth\OAuthProtectedResource;
use SimpleID\Protocols\OAuth\OAuthDynamicClient;
use SimpleID\Protocols\OAuth\OAuthAuthRequestEvent;
use SimpleID\Protocols\OAuth\OAuthAuthGrantEvent;
use SimpleID\Protocols\OAuth\OAuthTokenGrantEvent;
use SimpleID\Protocols\OAuth\Response;
use SimpleID\Store\StoreManager;
use SimpleID\Util\Events\BaseDataCollectionEvent;
use SimpleJWT\Util\Helper;
use SimpleJWT\JWT;
use SimpleJWT\InvalidTokenException;
use SimpleJWT\Crypt\Algorithm;
use SimpleJWT\Crypt\AlgorithmFactory;
use SimpleJWT\Keys\KeySet;
use \Web;

/**
 * Module for authenticating with OpenID Connect.
 */
class ConnectModule extends OAuthProtectedResource implements ProtocolResult {
    /**
     * @see SimpleID\Protocols\OAuth\OAuthProtectedResource::$oauth_include_request_body
     */
    protected $oauth_include_request_body = true;

    static function init($f3) {
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
            $this->logger->log(LogLevel::CRITICAL, 'Public JSON web key file not found.');
            $this->f3->error(500, $this->f3->get('intl.core.connect.missing_public_jwk', 'http://simpleid.org/docs/2/installing/#keys'));
        }

        if (!is_readable($config['private_jwks_file'])) {
            $this->logger->log(LogLevel::CRITICAL, 'Private JSON web key file not found.');
            $this->f3->error(500, $this->f3->get('intl.core.connect.missing_private_jwk', 'http://simpleid.org/docs/2/installing/#keys'));
        }
    }

    /**
     * Resolves an OpenID Connect authorisation request by decoding any
     * `request` and `request_uri` parameters.
     *
     */
    public function onOauthAuthResolve(OAuthEvent $event) {
        $store = StoreManager::instance();
        $web = Web::instance();
        $request = $event->getRequest();
        $response = $event->getResponse();

        // 1. Check if request_uri parameter is present.  If so, fetch the JWT
        // from this URL and place it in the request parameter
        if (isset($request['request_uri'])) {
            $this->logger->log(LogLevel::INFO, 'OpenID request object: getting object from ' . $request['request_uri']);
            
            $parts = parse_url($request['request_uri']);
            
            $http_response = new HTTPResponse($web->request($request['request_uri'], [ 'headers' => [ 'Accept' => 'application/jwt,text/plain,application/octet-stream' ] ]));

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
                AlgorithmFactory::addNoneAlg();
                $helper = new Helper($request['request']);
                $jwt = $helper->getJWTObject($set, $jwe_alg, $jwt_alg);
                $request->loadData($jwt->getClaims());
            } catch (\UnexpectedValueException $e) {
                $this->logger->log(LogLevel::ERROR, 'Invalid OpenID request object: ' . $e->getMessage());
                $response->setError('invalid_openid_request_object', $e->getMessage());
                return;
            }
        }
        AlgorithmFactory::removeNoneAlg();

        // 3. nonce
        if ($request->paramContains('scope', 'openid') && $request->paramContains('response_type', 'token') && !isset($request['nonce'])) {
            $this->logger->log(LogLevel::ERROR, 'Protocol Error: nonce not set when using implicit flow');
            $response->setError('invalid_request', 'nonce not set when using implicit flow')->renderRedirect();
            return;
        }
    }

    /**
     * Processes an OpenID Connect authorisation request.
     *
     * This hook is called as part of the OAuth authorisation process.  This
     * function performs additional checks required by the OpenID Connect
     * protocol, including processing the `prompt`, `max_age` and
     * `acr` paramters.
     *
     * @see SimpleID\Protocols\OAuth\OAuthProcessAuthRequestEvent
     */
    function onOAuthAuthRequestEvent(OAuthAuthRequestEvent $event) {
        $request = $event->getRequest();
        $store = StoreManager::instance();
        $auth = AuthManager::instance();

        $client = $store->loadClient($request['client_id'], 'SimpleID\Protocols\OAuth\OAuthClient');

        // Check 1: Check whether the prompt parameter is present in the request
        $request->setImmediate($request->paramContains('prompt', 'none'));

        if ($request->paramContains('prompt', 'login')) {
            $this->f3->set('message', $this->f3->get('intl.common.reenter_credentials'));
            $request->paramRemove('prompt', 'login');
            $event->setResult(self::CHECKID_REENTER_CREDENTIALS);
            return;
        }

        if ($request->paramContains('prompt', 'consent')) {
            $request->paramRemove('prompt', 'consent');
            $event->setResult(self::CHECKID_APPROVAL_REQUIRED);
            return;
        }

        // Check 2: If id_token_hint is provided, check that it refers to the current logged-in user
        if (isset($request['id_token_hint'])) {
            try {
                $jwt = JWT::deserialise($request['id_token_hint']);
                $claims = $jwt['claims'];
                $user_match = ($claims['sub'] == self::getSubject($auth->getUser(), $client));
            } catch (InvalidTokenException $e) {
                $user_match = false;
            }
            if (!$user_match) {
                $auth->logout();
                $event->setResult(self::CHECKID_LOGIN_REQUIRED);
                return;
            }
        }
        
        // Check 3: Check whether the max_age or acr parameters are present in the client defaults
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
            if (($auth_level < AuthManager::AUTH_LEVEL_CREDENTIALS) 
                || ((time() - $auth->getAuthTime()) > $max_age)) {
                $this->f3->set('message', $this->f3->get('intl.common.reenter_credentials'));
                $event->setResult(self::CHECKID_REENTER_CREDENTIALS);
                return;
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
            $event->setResult(self::CHECKID_INSUFFICIENT_TRUST);
            return;
        }
    }


    /**
     * Builds the OpenID Connect authentication response on a successful
     * authentication.
     *
     * The OpenID Connect authentication response is built on top of the OAuth
     * authorisation response and token responses.  It may include an ID token
     * containing the claims requested by the OpenID Connect client.
     * 
     * This function prepares the OpenID Connect claims to be returned by calling
     * the {@link buildClaims()} function with an `id_token` parameter.  This
     * function will then:
     *
     * - encode the claims in an ID token and return it as part of the authorisation
     *   response; and/or
     * - save the claims to be returned as part of the token response.
     * 
     * @see SimpleID\Protocols\OAuth\OAuthAuthGrantEvent
     */
    function onOAuthAuthGrantEvent(OAuthAuthGrantEvent $event) {
        // code: ?code / id_token
        // id_token: #id_token
        // id_token token: #access_token #id_token
        // code id_token: #code #id_token[c_hash] / id_token
        // code token: #code #access_token / id_token
        // code id_token token: #code #access_token #id_token[c_hash, at_hash] / id_token
        $request = $event->getRequest();
        $response = $event->getResponse();
        $authorization = $event->getAuthorization();
        $scopes = $event->getRequestedScope();

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

    /**
     * Processes an OpenID Connect token response.  An OpenID Connect token
     * response may contain an ID token containing the claims that the
     * OpenID Connect client requested earlier.
     * 
     * @see SimpleID\Protocols\OAuth\OAuthTokenGrantEvent
     */
    function onOAuthTokenGrantEvent(OAuthTokenGrantEvent $event) {
        $auth = $event->getAuthorization();
        $response = $event->getResponse();

        if (($event->getGrantType() == 'authorization_code') && isset($auth->additional['id_token_claims'])) {
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

    public function onOauthResponseTypes(BaseDataCollectionEvent $event) {
        $event->addResult('id_token');
    }

    /**
     * The UserInfo endpoint.  The UserInfo endpoint returns a set
     * of claims requested by the OpenID Connect client.
     */
    public function userinfo() {
        $this->checkHttps('error');

        $error = '';
        if (!$this->isTokenAuthorized('openid', $error)) {
            $this->unAuthorizedError($error, null, [], 'json');
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
     * @param \SimpleID\Models\User $user the user about which the ID
     * token is created
     * @param \SimpleID\Models\Client $client the client to which the
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
        $dispatcher = \Events::instance();

        $scope_info_event = new ScopeInfoCollectionEvent();
        $dispatcher->dispatch($scope_info_event);
        $scope_info = $scope_info_event->getScopeInfoForType('oauth');

        $claims = [];
        $claims['sub'] = self::getSubject($user, $client);

        if ($claims_requested != null) {
            foreach ($claims_requested as $claim => $properties) {
                switch ($claim) {
                    case 'acr':
                        // Processed later
                        break;
                    case 'updated_at':
                        // Not supported
                        break;
                    default:
                        $consent_scope = null;
                        foreach (array_keys($scope_info) as $scope => $settings) {
                            /** @var array $settings */
                            if (!isset($settings['claims'])) continue;
                            if (in_array($claim, $settings['claims'])) $consent_scope = $scope;
                        }
                        if ($consent_scope == null) break; // No consent given for this claim

                        if (isset($user['userinfo'][$claim])) {
                            $claims[$claim] = $user['userinfo'][$claim];
                            if ($claim == 'email') $claims['email_verified'] = false;
                            if ($claim == 'phone_number') $claims['phone_number_verified'] = false;
                        }
                        break;
                }
            }
        } else {
            foreach ([ 'profile', 'email', 'address', 'phone' ] as $scope) {
                if (in_array($scope, $scopes)) {
                    if (isset($scope_info[$scope]['claims'])) {
                        foreach ($scope_info[$scope]['claims'] as $claim) {
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
            $claims['auth_time'] = $auth->getAuthTime();
            $claims['acr'] = $auth->getACR();
        }

        $build_claims_event = new ConnectBuildClaimsEvent($user, $client, $context, $scopes, $claims_requested);
        $build_claims_event->addResult($claims);
        $dispatcher->dispatch($build_claims_event);

        return $build_claims_event->getResults();
    }

    /**
     * Obtains a `sub` (subject) claim for a user and client.
     *
     * The subject type can be public (which reflect the user's ID)
     * or pairwise.  The type chosen is dependent on the client's
     * registration settings.
     *
     * @param \SimpleID\Models\User $user the user about which the ID
     * token is created
     * @param \SimpleID\Models\Client $client the client to which the
     * ID token will be sent
     * @return string|null the subject
     */
    public static function getSubject($user, $client) {
        if (isset($client['connect']['sector_identifier_uri'])) {
            $sector_id = parse_url($client['connect']['sector_identifier_uri'], PHP_URL_HOST);
        } elseif (is_string($client['oauth']['redirect_uris'])) {
            $sector_id = parse_url($client['oauth']['redirect_uris'], PHP_URL_HOST);
        } elseif (is_array($client['oauth']['redirect_uris']) && (count($client['oauth']['redirect_uris']) == 1)) {
            $sector_id = parse_url($client['oauth']['redirect_uris'][0], PHP_URL_HOST);
        } else {
            $sector_id = $client->getStoreID();
        }

        $claims = [];

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
     * @see ScopeInfoCollectionEvent
     */
    public function onScopeInfoCollectionEvent(ScopeInfoCollectionEvent $event) {
        $event->addScopeInfo('oauth', [
            'openid' => [
                'description' => $this->f3->get('intl.common.scope.id'),
                'weight' => -1
            ],
            'profile' => [
                'description' => $this->f3->get('intl.common.scope.profile'),
                'claims' => ['name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale' ]
            ],
            'email' => [
                'description' => $this->f3->get('intl.common.scope.email'),
                'claims' => [ 'email' ]
            ],
            'address' => [
                'description' => $this->f3->get('intl.common.scope.address'),
                'claims' => [ 'address' ]
            ],
            'phone' => [
                'description' => $this->f3->get('intl.common.scope.phone'),
                'claims' => [ 'phone_number' ]
            ]
        ]);
    }


    /**
     * Displays the OpenID Connect configuration file for this installation.
     *
     */
    public function openid_configuration() {
        $mgr = ModuleManager::instance();
        $dispatcher = \Events::instance();

        header('Content-Type: application/json');
        header('Content-Disposition: inline; filename=openid-configuration');

        $scope_info_event = new ScopeInfoCollectionEvent();
        $dispatcher->dispatch($scope_info_event);
        $scopes = $scope_info_event->getScopesForType('oauth');

        $jwt_signing_algs = AlgorithmFactory::getSupportedAlgs(Algorithm::SIGNATURE_ALGORITHM);
        $jwt_encryption_algs = AlgorithmFactory::getSupportedAlgs(Algorithm::KEY_ALGORITHM);
        $jwt_encryption_enc_algs = AlgorithmFactory::getSupportedAlgs(Algorithm::ENCRYPTION_ALGORITHM);

        $claims_supported = [ 'sub', 'iss', 'auth_time', 'acr' ];
        foreach ($scopes as $scope => $settings) {
            if (isset($settings['claims'])) {
                $claims_supporteds = array_merge($claims_supported, $settings['claims']);
            }
        }

        $token_endpoint_auth_methods_supported = [ 'client_secret_basic', 'client_secret_post' ];
        
        $config = [
            'issuer' => $this->getCanonicalHost(),
            'authorization_endpoint' => $this->getCanonicalURL('@oauth_auth', '', 'https'),
            'token_endpoint' => $this->getCanonicalURL('@oauth_token', '', 'https'),
            'userinfo_endpoint' => $this->getCanonicalURL('@connect_userinfo', '', 'https'),
            'jwks_uri' => $this->getCanonicalURL('@connect_jwks', '', 'https'),
            'scopes_supported' => $scopes,
            'response_types_supported' => [ 'code', 'token', 'id_token', 'id_token token', 'code token', 'code id_token', 'code id_token token' ],
            'response_modes_supported' => Response::getResponseModesSupported(),
            'grant_types_supported' => [ 'authorization_code', 'refresh_token' ],
            'acr_values_supported' => [],
            'subject_types_supported' => [ 'public', 'pairwise' ],
            'userinfo_signing_alg_values_supported' => $jwt_signing_algs,
            'userinfo_encryption_alg_values_supported' => $jwt_encryption_algs,
            'userinfo_encryption_enc_alg_values_supported' => $jwt_encryption_enc_algs,
            'id_token_signing_alg_values_supported' => $jwt_signing_algs,
            'id_token_encrpytion_alg_values_supported' => $jwt_encryption_algs,
            'id_token_encrpytion_enc_alg_values_supported' => $jwt_encryption_enc_algs,
            'request_object_signing_alg_values_supported' => array_merge($jwt_signing_algs, [ 'none' ]),
            'request_object_encryption_alg_values_supported' => $jwt_encryption_algs,
            'request_object_encryption_enc_alg_values_supported' => $jwt_encryption_enc_algs,
            'token_endpoint_auth_methods_supported' => $token_endpoint_auth_methods_supported,
            'claim_types_supported' => [ 'normal' ],
            'claims_supported' => $claims_supported,
            'claims_parameter_supported' => true,
            'request_parameter_supported' => true,
            'request_uri_parameter_supported' => true,
            'require_request_uri_registration' => false,
            'service_documentation' => 'https://simpleid.org/docs/'
        ];

        $config_event = new BaseDataCollectionEvent('connect_configuration');
        $config_event->addResult($config);
        $dispatcher->dispatch($config_event);
        print json_encode($config_event->getResults());
    }


    /**
     * Displays the JSON web key for this installation.
     */
    public function jwks() {
        $config = $this->f3->get('config');

        if (!isset($config['public_jwks_file'])) {
            $this->f3->status(404);
            $this->fatalError($this->f3->get('intl.core.connect.missing_jwks'));
        }
        
        $set = new KeySet();
        $set->load(file_get_contents($config['public_jwks_file']));

        if (!$set->isPublic()) {
            $this->f3->status(401);
            $this->fatalError($this->f3->get('intl.core.connect.jwks_not_public'));
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
