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

use \Base;
use \Prefab;
use Psr\Log\LogLevel;
use SimpleID\ModuleManager;
use SimpleID\Crypt\Random;
use SimpleID\Store\StoreManager;
use SimpleID\Util\SecurityToken;

/**
 * The manager handling OAuth based authentication
 */
class OAuthManager extends Prefab {

    protected $f3;
    protected $logger;
    protected $mgr;

    private $access_token = NULL;
    private $client_auth_method;

    public function __construct() {
        $this->f3 = Base::instance();
        $this->logger = $this->f3->get('logger');
        $this->mgr = ModuleManager::instance();
    }

    /**
     * Authenticates the OAuth client.
     *
     * This function detects whether credentials for an OAuth client is
     * presented in the `Authorization` header or the POST body.
     */
    public function initClient() {
        $this->logger->log(LogLevel::DEBUG, 'SimpleID\Protocols\OAuth\OAuthManager->initClient');

        $store = StoreManager::instance();

        $request = new Request();
        $header = $request->getAuthorizationHeader(true);

        if (($header != null) && ($header['#scheme'] == 'Basic')) {
            $client_auth_method = 'client_secret_basic';
            $client_id = $header['#username'];
            $client_secret = $header['#password'];
        }

        if (!$client_id && $this->f3->exists('POST.client_id') && $this->f3->exists('POST.client_secret')) {
            $client_auth_method = 'client_secret_post';
            $client_id = $this->f3->get('POST.client_id');
            $client_secret = $this->f3->get('POST.client_secret');
        }

        if ($client_id) {
            $client = $store->loadClient($client_id, 'SimpleID\Protocols\OAuth\OAuthClient');
            
            if ($client['oauth']['client_secret'] != $client_secret) return;
            
            $this->client_auth_method = $client_auth_method;
        } else {
            $results = $this->mgr->invokeAll('oAuthInitClient', $request);
            $results = array_merge(array_diff($results, [ NULL ]));
            if (count($results) == 1) {
                $client = $results[0]['#client'];
                $this->client_auth_method = $results[0]['#client_auth_method'];
            }
        }
        $this->f3->set('oauth_client', $client);

        $this->logger->log(LogLevel::INFO, 'OAuth client: ' . $client_id . ' [' . $this->client_auth_method . ']');
    }


    /**
     * Returns whether an authenticated OAuth client is present.
     *
     * If the `$send_challenge` parameter is set to true, a `WWW-Authenticate`
     * header will be sent if an authenticated OAuth client is
     * not present
     *
     * @param bool $send_challenge if a challenge is to be sent
     * @param array $auth_methods expected authentication method
     * @return bool true if an authenticated OAuth client is present
     */
    public function isClientAuthenticated($send_challenge = false, $auth_methods = null) {
        $this->logger->log(LogLevel::DEBUG, 'SimpleID\Protocols\OAuth\OAuthManager->isClientAuthenticated');

        $result = $this->f3->exists('oauth_client');
        if ($result && ($auth_methods != null)) {
            if (!is_array($auth_methods)) $auth_methods = [ $auth_methods ];
            $result = in_array($this->client_auth_method, $auth_methods);
            if (!$result) {
                $this->logger->log(LogLevel::ERROR, 'Unexpected authentication method: ' . $this->client_auth_method . '; expecting ' . implode(',', $auth_methods));
            }
        }

        if ($result) {
            return true;
        } else {
            if ($send_challenge) {
                $auth_method_map = [
                    'client_secret_basic' => 'Basic'
                ];
                $http_auth_method = $auth_method_map[$auth_method];
                $this->f3->status(401);
                header('WWW-Authenticate: ' . $http_auth_method . ' realm="'. $this->f3->get('REALM') . '"');
            }

            return false;
        }
    }

    /**
     * Returns the authenticated OAuth client, if any.
     *
     * @return Client the authenticated OAuth client, or null
     */
    public function getClient() {
        if ($this->f3->exists('oauth_client')) return $this->f3->get('oauth_client');
        return null;
    }

    /**
     * Returns the method used to authenticate the current OAuth client.
     *
     * @param string the authentication method
     */
    public function getClientAuthMethod() {
        return $this->client_auth_method;
    }

    /**
     * Authenticates the OAuth access token.
     *
     * This function detects whether an access token has been presented.
     *
     * @param bool $include_request_body if true, also detects access tokens
     * from the request body
     */
    public function initAccessToken($include_request_body = false) {
        $this->logger->log(LogLevel::DEBUG, 'SimpleID\Protocols\OAuth\OAuthManager->initAccessToken');

        $bearer_token = $this->initBearerAccessToken($include_request_body);
        if ($bearer_token) {
            $this->access_token = AccessToken::decode($bearer_token);
            return;
        }

        // Try other token types
        $results = $this->mgr->invokeAll('oAuthInitAccessToken');
        $results = array_merge(array_diff($results, [ NULL ]));
        if (count($results) == 1) $this->access_token = $results[0];
    }

    /**
     * Authenticates the OAuth bearer access token.
     *
     * @param bool $include_request_body if true, also detects access tokens
     * from the request body
     */
    protected function initBearerAccessToken($include_request_body = false) {
        $encoded_token = null;

        $request = new Request();
        $header = $request->getAuthorizationHeader();

        if ($header) {
            if ($header['#scheme'] == 'Bearer')
                $encoded_token = $header['#credentials'];
        }

        if (!$encoded_token && $include_request_body && $this->f3->exists('REQUEST.access_token')) {
            $encoded_token = $this->f3->get('REQUEST.access_token');
        }

        return $encoded_token;
    }

    /**
     * Returns the access token included in the request.
     *
     * @return AccessToken the access token
     */
    public function getAccessToken() {
        return $this->access_token;
    }

    /**
     * Returns whether the current access token is authorised under the
     * specified scope.
     *
     * @param array|string $scope the scope
     * @param string &$error the error code returned if the access token
     * is not authorised
     * @return bool true if the access token is authorised
     */
    public function isTokenAuthorized($scope, &$error = null) {
        if (!$this->access_token) {
            if ($error !== null) $error = '';
            return false;
        }
        if (!$this->access_token->isValid()) {
            if ($error !== null) $error = 'invalid_token';
            return false;
        }
        if (!$this->access_token->hasScope($scope)) {
            if ($error !== null) $error = 'insufficient_scope';
            return false;
        }

        return true;
    }
}
?>
