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
use SimpleID\Crypt\Random;
use SimpleID\Module;
use SimpleID\Protocols\HTTPResponse;
use SimpleID\Protocols\OAuth\Authorization;
use SimpleID\Protocols\OAuth\OAuthProtectedResource;
use SimpleID\Protocols\OAuth\Response;
use SimpleID\Store\StoreManager;
use SimpleID\Util\RateLimiter;
use SimpleID\Util\Events\BaseDataCollectionEvent;

/**
 * Module implementing the OpenID Connect Dynamic Client Registration
 * specification.
 *
 * @link http://openid.net/specs/openid-connect-registration-1_0.html
 */
class ConnectClientRegistrationModule extends OAuthProtectedResource {

    const CLIENT_REGISTRATION_INIT_SCOPE = 'tag:simpleid.sf.net,2014:client_register:init';
    const CLIENT_REGISTRATION_ACCESS_SCOPE = 'tag:simpleid.sf.net,2014:client_register:access';

    /** @var array<string, string>|null */
    static protected $metadata_map = NULL;

    static function init($f3) {
        $f3->route('POST @connect_client_register: /connect/client', 'SimpleID\Protocols\Connect\ConnectClientRegistrationModule->register');
        $f3->map('/connect/client/@client_id', 'SimpleID\Protocols\Connect\ConnectClientRegistrationModule');
    }

    public function __construct() {
        parent::__construct();

        if (self::$metadata_map == NULL) {
            self::$metadata_map = [
                'client_name' => 'client_name',
                'client_uri' => 'client_uri',
                'client_secret' => 'oauth.client_secret',
                'redirect_uris' => 'oauth.redirect_uris',
                'application_type' => 'oauth.application_type',
                'token_endpoint_auth_method' => 'oauth.token_endpoint_auth_method',
                'response_types' => 'oauth.response_types',
                'grant_types' => 'oauth.grant_types',
                'contacts' => 'oauth.contacts',
                'logo_uri' => 'oauth.logo_uri',
                'policy_uri' => 'oauth.policy_uri',
                'tos_uri' => 'oauth.tos_uri',
                'jwk_uri' => 'oauth.jwk_uri',
                'jwks' => 'oauth.jwks',
                'sector_identifier_uri' => 'connect.sector_identifier_uri',
                'subject_type' => 'connect.subject_type',
                'id_token_signed_response_alg' => 'connect.id_token_signed_response_alg',
                'id_token_encrypted_response_alg' => 'connect.id_token_encrypted_response_alg',
                'id_token_encrypted_response_enc' => 'connect.id_token_encrypted_response_enc',
                'userinfo_signed_response_alg' => 'connect.userinfo_signed_response_alg',
                'userinfo_encrypted_response_alg' => 'connect.userinfo_encrypted_response_alg',
                'userinfo_encrypted_response_enc' => 'connect.userinfo_encrypted_response_enc',
                'request_object_signing_alg' => 'connect.request_object_signing_alg',
                'request_object_encryption_alg' => 'connect.request_object_encryption_alg',
                'request_object_encryption_enc' => 'connect.request_object_encryption_enc',
                'token_endpoint_auth_signing_alg' => 'connect.token_endpoint_auth_signing_alg',
                'default_max_age' => 'connect.default_max_age',
                'require_auth_time' => 'connect.require_auth_time',
                'default_acr_values' => 'connect.default_acr_values',
                'initiate_login_uri' => 'connect.initiate_login_uri',
                'request_uris' => 'connect.request_uris',
                'post_logout_redirect_uris' => 'connect.post_logout_redirect_uris',
            ];
        }
    }

    /**
     * Registration endpoint
     * 
     * @return void
     */
    public function register() {
        $rand = new Random();
        $response = new Response();

        $this->checkHttps('error');
        $this->logger->log(LogLevel::DEBUG, 'SimpleID\Protocols\Connect\ConnectClientRegistrationModule->register');

        // Access token OR rate limit
        if (!$this->isTokenAuthorized(self::CLIENT_REGISTRATION_INIT_SCOPE)) {
            $limiter = new RateLimiter('connect_register');

            if (!$limiter->throttle()) {
                header('Retry-After: ' . $limiter->getInterval());
                // We never display a log for rate limit errors
                $response->setError('invalid_request', 'client has been blocked from making further requests')->renderJSON(429);
                return;
            }
        }

        if (!$this->f3->exists('BODY')) {
            $response->setError('invalid_request')->renderJSON();
            return;
        }

        $request = json_decode($this->f3->get('BODY'), true);
        if ($request == null) {
            $response->setError('invalid_request', 'unable to parse body')->renderJSON();
            return;
        }

        if (!isset($request['redirect_uris'])) {
            $response->setError('invalid_redirect_uri', 'redirect_uris missing')->renderJSON();
            return;
        }

        // Verify redirect_uri based on application_type
        $application_type = (isset($request['application_type'])) ? $request['application_type'] : 'web';
        $grant_types = (isset($request['grant_types'])) ? $request['grant_types'] : [ 'authorization_code' ];

        foreach ($request['redirect_uris'] as $redirect_uri) {
            $parts = parse_url($redirect_uri);

            if (isset($parts['fragment'])) {
                $response->setError('invalid_redirect_uri', 'redirect_uris cannot contain a fragment')->renderJSON();
                return;
            }

            if (($application_type == 'web') && in_array('implicit', $grant_types)) {
                if ((strtolower($parts['scheme']) != 'https') || (strtolower($parts['host']) == 'localhost') && ($parts['host'] == '127.0.0.1')) {
                    $response->setError('invalid_redirect_uri', 'implicit grant type must use https URIs')->renderJSON();
                    return;
                }
            } elseif ($application_type == 'native') {
                // Native Clients MUST only register redirect_uris using custom URI schemes or URLs using the http: scheme with localhost as the hostname.
                // Authorization Servers MAY place additional constraints on Native Clients.
                // Authorization Servers MAY reject Redirection URI values using the http scheme, other than the localhost case for Native Clients.
                // The Authorization Server MUST verify that all the registered redirect_uris conform to these constraints. This prevents sharing a Client ID across different types of Clients.
                if (((strtolower($parts['scheme']) == 'http') && ((strtolower($parts['host']) != 'localhost') || ($parts['host'] != '127.0.0.1')))
                    || (strtolower($parts['scheme']) == 'https')) {
                    $response->setError('invalid_redirect_uri', 'native clients cannot use https URIs')->renderJSON();
                    return;
                }
            }
        }
        
        // Verify sector_identifier_url
        $subject_type = (isset($request['subject_type'])) ? $request['subject_type'] : 'public';
        if (isset($request['sector_identifier_uri'])) {
            if (!$this->verifySectorIdentifier($request['sector_identifier_uri'], $request['redirect_uris'])) {
                $response->setError('invalid_client_metadata', 'cannot verify sector_identifier_uri')->renderJSON();
                return;
            }
        }

        $client = new ConnectDynamicClient();
        $client_id = $client->getStoreID();

        // Map data
        foreach ($request as $name => $value) {
            $parts = explode('#', $name, 2);
            $client_path = (isset(self::$metadata_map[$parts[0]])) ? self::$metadata_map[$parts[0]] : 'connect.' . $parts[0];
            if (isset($parts[1])) $client_path .= '#' . $parts[1];
            $client->pathSet($client_path, $value);
        }

        $client->fetchJWKs();

        $response->loadData($request);
        $response->loadData([
            'client_id' => $client->getStoreID(),            
            'registration_client_uri' => $this->getCanonicalURL('connect/client/' . $client->getStoreID()),
            'client_id_issued_at' => time(),
        ]);

        if ($client['oauth']['token_endpoint_auth_method'] != 'none') {
            $client->pathSet('oauth.client_secret', $rand->secret());
            $response['client_secret'] = $client['oauth']['client_secret'];
            $response['client_secret_expires_at'] = 0;
        }

        $store = StoreManager::instance();
        $store->saveClient($client);

        $this->logger->log(LogLevel::INFO, 'Created dynamic client: ' . $client_id);

        $auth = new Authorization($client, $client, self::CLIENT_REGISTRATION_ACCESS_SCOPE);
        $store->saveAuth($auth);
        $token = $auth->issueAccessToken([ self::CLIENT_REGISTRATION_ACCESS_SCOPE ]);
        $response['registration_access_token'] = $token['access_token'];

        $this->f3->status(201);
        $response->renderJSON();
    }

    /**
     * Configuration endpoint
     * 
     * @return void
     */
    public function get() {
        $this->checkHttps('error');
        $client_id = $this->f3->get('PARAMS.client_id');

        if (!$this->isTokenAuthorized(self::CLIENT_REGISTRATION_ACCESS_SCOPE)
            || ($this->getAccessToken()->getAuthorization()->getClient()->getStoreID() != $client_id)) {
            $this->unauthorizedError('invalid_token');
            return;
        }

        $store = StoreManager::instance();
        $client = $store->loadClient($client_id);

        if (($client == NULL) || !is_a($client, 'SimpleID\Protocols\Connect\ConnectDynamicClient')) {
            $this->f3->status(404);
            $this->fatalError($this->f3->get('intl.common.not_found'));
            return;
        }

        header('Content-Type: application/json');
        header('Content-Disposition: inline');
        print json_encode($client->getDynamicClientInfo());
    }

    /**
     * @return void
     */
    public function onConnectConfiguration(BaseDataCollectionEvent $event) {
        $event->addResult([ 'registration_endpoint' => $this->getCanonicalURL('@connect_client_register') ]);
    }

    /**
     * Verifies a sector identifier URI.
     *
     * This function retrieves the JSON document specified by `$sector_identifier_uri` and checks
     * whether the URIs in that document are contained in `$expected_redirect_uris`
     *
     * @param string $sector_identifier_uri the sector identifier URI
     * @param array<string> $expected_redirect_uris an array of URIs that the document in `$sector_identifier_uri`
     * is expected to match
     * @return bool true if the sector identifier is verified
     */
    protected function verifySectorIdentifier($sector_identifier_uri, $expected_redirect_uris) {
        $web = \Web::instance();

        $this->logger->log(LogLevel::INFO, 'OAuth dynamic client registration request: verifying OpenID Connect sector_identifier_uri ' . $sector_identifier_uri);

        if (parse_url($sector_identifier_uri, PHP_URL_SCHEME) != 'https') {
            $this->logger->log(LogLevel::ERROR, 'Not https:' . $sector_identifier_uri);
            return false;
        }

        $response = new HTTPResponse($web->request($sector_identifier_uri, [ 'headers' => [ 'Accept' => 'application/json' ] ]));
        
        if ($response->isHttpError()) {
            $this->logger->log(LogLevel::ERROR, 'Cannot retrieve sector_identifier_uri:' . $sector_identifier_uri);
            return false;
        }
        
        $test_redirect_uris = json_decode($response->getBody(), true);
        if ($test_redirect_uris == NULL) {
            $this->logger->log(LogLevel::ERROR, 'Invalid sector_identifier_uri: not valid JSON');
            return false;
        } elseif ((count(array_diff($expected_redirect_uris, $test_redirect_uris)) > 0) || (count(array_diff($test_redirect_uris, $expected_redirect_uris)) > 0)) {
            $this->logger->log(LogLevel::ERROR, 'Redirect URIs in sector_identifier_uri do not match redirect_uris');
            return false;
        } else {
            $this->logger->log(LogLevel::DEBUG, 'sector_identifier_uri verified');
            return true;
        }
    }
}


?>
