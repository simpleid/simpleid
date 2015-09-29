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
 */

namespace SimpleID\Protocols\OAuth;

use SimpleID\Crypt\Random;
use SimpleID\Store\StoreManager;

/**
 * A class representing an OAuth authorization code.
 *
 * A new authorization code is created using the {@link create()} static
 * method.
 *
 * An existing authorization code (which may or may not be valid) can be
 * decoded using the {@link decode()} static method.  You should always
 * use the {@link isValid()} method to check whether the authorization code
 * is valid before using it to issue tokens, etc.
 */
class Code implements TokenSource {
    /**
     * Separator between the authorization code and the fully-qualified
     * authorisation ID.
     *
     * @see Authorization
     */
    const CODE_SEPARATOR = '.';

    private $cid;
    private $aid;
    private $auth_state;
    
    private $redirect_uri;
    private $scope;
    private $expires;
    private $additional;

    private $is_valid = false;

    /**
     * Creates an authorization code.  This is used by this class's static
     * methods to create an instance of this class.
     */
    protected function __construct() {

    }

    /**
     * Decodes an existing authorization code.
     *
     * Note that this method does not check whether the authorization
     * code is valid issued or has not been revoked.  You should always
     * use the {@link isValid()} method to check the validity of the
     * authorization code before using it to issue tokens.
     *
     * @param string $code the authorization code
     * @return Code the authorization code object
     */
    static public function decode($code) {
        $results = self::load($code);
        if ($results == null) {
            $results = new Code();
            list($results->cid, $fqaid) = explode(self::CODE_SEPARATOR, $code, 2);
            list($results->auth_state, $results->aid) = explode(Authorization::AUTH_STATE_SEPARATOR, $fqaid, 2);
            $results->is_valid = false;
        }

        return $results;
    }

    /**
     * Loads an existing authorization code.
     *
     * @param string $code the authorization code
     * @return Code the authorization code object
     */
    static protected function load($code) {
        $cache = \Cache::instance();

        if (!$cache->exists($code . '.code')) return null;

        $payload = $cache->get($code . '.code');
        if ($payload->expires < time()) return null;
        $payload->is_valid = true;
        return $payload;
    }

    /**
     * Creates an authorization code.
     *
     * Once the authorization code object has been created, the code can be retrieved using
     * the {@link getCode()} method.
     *
     * @param Authorization $authorization the authorization that wishes to generate
     * this code
     * @param string|null $redirect_uri the redirect_uri parameter in the authorisation request, if
     * present
     * @param array $scope the allowed scope - this should be a subset of the scope provided by the
     * authorization
     * @param array $additional additional data to be stored in the authorization code
     * @return Code the authorization code object
     */
    static public function create($authorization, $redirect_uri, $scope, $additional = array()) {
        $code = new Code();
        $rand = new Random();
        $cache = \Cache::instance();

        $code->cid = $rand->id();
        $code->aid = $authorization->getStoreID();
        $code->auth_state = $authorization->getAuthState();
        $code->redirect_uri = $redirect_uri;
        $code->scope = (!is_array($scope)) ? explode(' ', $scope) : $scope;
        $code->additional = $additional;
        $code->expires = time() + SIMPLEID_INSTANT_TOKEN_EXPIRES_IN;

        $cache->set($code->getCode() . '.code', $code, SIMPLEID_INSTANT_TOKEN_EXPIRES_IN);

        $code->is_valid = true;

        return $code;
    }

    /**
     * Determine whether an authorization code is valid.
     *
     * An authorization code is valid if:
     *
     * - it is created directly by the {@link create()} static method; or
     * - it has been decoded using the {@link decode()} static method, and
     * has been validated by SimpleID.
     *
     * @return bool true if the authorization code is valid
     */
    public function isValid() {
        return $this->is_valid;
    }

    /**
     * Returns the authorization code.
     *
     * @return string the authorization code
     */
    public function getCode() {
        return $this->cid . self::CODE_SEPARATOR . $this->auth_state . Authorization::AUTH_STATE_SEPARATOR . $this->aid;
    }

    /**
     * Returns the OAuth authorization that generated this code.
     *
     * If the authorization has been revoked, or is otherwise invalid, since
     * the authorization code has been issued, this function will return
     * `null`.
     *
     * @return Authorization the OAuth authorization or `null`.
     */
    public function getAuthorization() {
        $store = StoreManager::instance();
        $authorization = $store->loadAuth($this->aid);
        if ($authorization == null) return null;
        if ($authorization->getAuthState() != $this->auth_state) return null;
        return $authorization;
    }

    /**
     * Returns the redirect_uri bound to this authorization code.
     *
     * If a `redirect_uri` parameter is present in the authorization request,
     * then the authorization code is bound to that `redirect_uri`.  This
     * redirect_uri, if present, must be checked against the token request
     * before an access token can be issued.
     *
     * If a `redirect_uri` parameter is not present in the authorization request,
     * i.e. the pre-registered redirect URI is used, then this function will
     * return `null`.
     *
     * @return string the redirect URI
     */
    public function getRedirectURI() {
        return $this->redirect_uri;
    }

    /**
     * Returns the scope authorised by this authorization code.  Access tokens
     * issued from this authorization code must have this scope.
     *
     * @return array the scope
     */
    public function getScope() {
        return $this->scope;
    }

    /**
     * Returns additional data associated with this authorization code.
     *
     * @return array the additional data
     */
    public function getAdditional() {
        return $this->additional;
    }

    /**
     * Deletes the authorization code from the cache, rendering it invalid.
     */
    public function clear() {
        $cache = \Cache::instance();
        $cache->clear($this->getCode() . '.code');
    }

    public function getSourceRef() {
        return substr($this->cid, -9);
    }
}

?>