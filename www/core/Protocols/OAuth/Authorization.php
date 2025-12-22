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
 */

namespace SimpleID\Protocols\OAuth;

use \Cache;
use SimpleID\Crypt\Random;
use SimpleID\Store\Storable;
use SimpleID\Store\StoreManager;
use SimpleID\Crypt\SecurityToken;
use SimpleID\Crypt\OpaqueIdentifier;


/**
 * An OAuth authorisation.
 *
 * An OAuth authorisation permits an OAuth *client* to access resources with
 * a specified *scope* owned by the resource *owner*.  Authorisation codes,
 * access and refresh tokens are issued based on this authorisation.
 *
 * Within SimpleID, the owner (usually a user, but can sometimes be the
 * client object itself) and the client must be {@link Storable}.
 *
 * Each authorisation in SimpleID contains a randomly generated *authorisation state*.
 * The authorisation state is stored permanently along with the authorisation.
 * An authorisation state changes when:
 *
 * - a new authorisation is requested with a scope that is narrower (but not
 * wider) than the scope stored with the authorisation
 * - the user revokes the authorisation
 * - a token grant (e.g. authorisation code or refresh token) is consumed
 * - a security incident occurs
 *
 * Authorisation codes, access and refresh tokens are issued based on a particular
 * authorisation state.  Therefore, if the authorisation state changes, all of
 * these credentials are automatically revoked.
 *
 * The *authorisation ID* is a hash of the client and owner IDs.  The
 * *fully qualified authorisation ID* is the authorisation ID along with the current
 * authorisation state.
 *
 */
class Authorization implements Storable {

    /** Separator for the authorisation ID and the authorisation state */
    const AUTH_STATE_SEPARATOR = '.';

    /** @var string */
    private $id;

    /** @var string */
    private $auth_state;
    
    /** @var string the type and ID of the resource owner */
    protected $owner_ref;
    /** @var string the type and ID of the client */
    protected $client_ref;
    /** @var array<string> the scope of the authorisation */
    protected $available_scope;

    /** @var bool whether refresh tokens are issued */
    protected $issue_refresh_token = true;

    /** @var array<string, mixed> additional data to be stored with the authorization */
    public $additional = [];

    /**
     * Creates an authorisation.
     *
     * Once the authorisation is created, it needs to be stored using the
     * {@link \SimpleID\Store\StoreManager::save()} method.
     *
     * @param Storable $owner the Storable object representing the resource
     * owner
     * @param Storable $client the Storable object representing the
     * client
     * @param string|array<string> $scope a space-delimited string representing the scope
     * of the authorization
     * @param bool $issue_refresh_token whether to issue a refresh token if
     * permitted
     * @param string|null $auth_state an existing authorisation state, or null to
     * reset the authorisation state
     */
    public function __construct($owner, $client, $scope = '', $issue_refresh_token = true, $auth_state = NULL) {
        $this->owner_ref = $owner->getStoreType() . ':' . $owner->getStoreID();
        $this->client_ref = $client->getStoreType() . ':' . $client->getStoreID();
        $this->available_scope = (!is_array($scope)) ? explode(' ', $scope) : $scope;

        $this->id = self::buildID($owner, $client);
        if ($auth_state == NULL) {
            $this->resetAuthState();
        } else {
            $this->auth_state = $auth_state;
        }

        $this->issue_refresh_token = $issue_refresh_token;
    }

    /**
     * Returns the resource owner
     *
     * @return Storable the resource owner
     */
    public function getOwner() {
        $args = func_get_args();
        return $this->getStorable($this->owner_ref, $args);
    }

    /**
     * Returns the client
     *
     * @return Storable the client
     */
    public function getClient() {
        $args = func_get_args();
        return $this->getStorable($this->client_ref, $args);
    }

    /**
     * Returns a Storable object based on a reference.
     *
     * A reference of a Storable object is its store type (from 
     * {@link SimpleID\Store\Storable::getStoreType()}) and its ID (from
     * {@link SimpleID\Store\Storable::getStoreID()}), separated by a colon.
     *
     * @param string $ref the reference to the storable object
     * @param array<mixed> $args additional parameters
     * @return Storable the storable object or null
     */
    protected function getStorable($ref, $args = []) {
        $store = StoreManager::instance();
        $f3 = \Base::instance();

        list($type, $id) = explode(':', $ref, 2);
        array_unshift($args, $id);
        return call_user_func_array([ $store, 'load' . ucfirst($f3->camelCase($type)) ], $args);
    }

    /**
     * Returns the scope of the authorisation.
     *
     * @return array<string> the scope of this authorisation
     */
    public function getScope() {
        return $this->available_scope;
    }

    /**
     * Changes the scope of the authorisation.
     *
     * If the new scope is narrower than the current scope (i.e contains
     * fewer elements), then the authorisation state is reset.  The new
     * authorisation state can be obtained using the {@link getAuthState()}
     * method.
     *
     * @param string|array<string> $scope the new scope as a space-delimited string
     * or an array
     * @return void
     */
    public function setScope($scope) {
        if (!is_array($scope)) $scope = explode(' ', $scope);

        if (count(array_diff($this->available_scope, $scope)) > 0) {
            // Scope narrowing - reset auth state
            $this->resetAuthState();
            // Note that may be scope in $scope that are not yet in $available_scope
            $this->available_scope = array_intersect($this->available_scope, $scope);
        }

        $added_scope = array_diff($scope, $this->available_scope);
        if (count($added_scope) > 0) {
            // Scope widening
            $this->available_scope = array_merge($this->available_scope, $added_scope);
        }
    }

    /**
     * Checks whether the authorisation covers a specified scope.
     *
     * This method will return true if the authorisation covers *all* of the
     * scope specified by `$scope`.
     *
     * @param string|array<string> $scope the scope to test
     * @return bool true if the authorisation covers all of the specified
     * scope
     */
    public function hasScope($scope) {
        if (!is_array($scope)) $scope = explode(' ', $scope);
        return (count(array_diff($scope, $this->available_scope)) == 0);
    }

    /**
     * Filter a scope parameter so that it is equal to or narrower than
     * the scope authorised under this authorization.
     *
     * @param string|array<string> $scope the scope to filter
     * @return array<string> the filtered scope
     */
    public function filterScope($scope) {
        if (!is_array($scope)) $scope = explode(' ', $scope);
        return array_intersect($this->available_scope, $scope);
    }

    /**
     * Returns the current authorisation state
     *
     * @return string the authorisation state
     */
    public function getAuthState() {
        return $this->auth_state;
    }

    /**
     * Resets the current authorisation state
     *
     * @return string the new authorisation state
     */
    public function resetAuthState() {
        $rand = new Random();
        $this->auth_state = substr($rand->secret(7), -9);
        return $this->auth_state;
    }

    /**
     * Returns whether a refresh token will be issued if permitted.
     *
     * If this is true and the OAuth specification permits a refresh token
     * to be issued, a refresh token ill be issued when {@link issueCode()} is
     * called.
     *
     * @return bool true a refresh token will be issued
     */
    public function getIssueRefreshToken() {
        return $this->issue_refresh_token;
    }

    /**
     * Creates an OAuth authorisation code.
     *
     * @param string $redirect_uri the redirect URI associated with the code
     * @param string|array<string> $scope the allowed scope - this should be a subset of
     * the scope provided by the authorisation, or null if all of the authorisation's
     * scope is to be included
     * @param array<string, mixed> $additional additional data to be stored in the code
     * @return string the authorisation code
     */
    public function issueCode($redirect_uri, $scope = null, $additional = []) {
        if ($scope == null) $scope = $this->available_scope;
        $code = Code::create($this, $redirect_uri, $scope, $additional);

        return $code->getCode();
    }

    /**
     * Issues an access token and, if set, a refresh token.
     *
     * This function calls {@link issueAccessToken()} to issue an access token.
     * It will also call {@link issueRefreshToken()} if the authorisation was
     * created with $issue_refresh_token set to true.
     *
     * @param array<string> $scope the scope to be included in the tokens
     * @param int $expires_in the time over which the access token will be valid,
     * in seconds, or {@link SimpleID\Protocols\OAuth\Token::TTL_PERPETUAL} if the token is not to expire
     * @param TokenGrantType $grant the grant, if any, from which the token is to be
     * generated
     * @param array<string, mixed> $additional additional data to be stored on the server for this
     * token
     * @return array<string, string> an array of parameters that can be included in the OAuth token
     * endpoint response
     */
    public function issueTokens($scope = [], $expires_in = Token::TTL_PERPETUAL, $grant = null, $additional = []) {
        $results = $this->issueAccessToken($scope, $expires_in, $grant, $additional);
        
        if ($this->issue_refresh_token) {
            $results = array_merge($results, $this->issueRefreshToken($scope, $grant, $additional));
        }
        return $results;
    }

    /**
     * Issues an access token.
     *
     * @param array<string> $scope the scope to be included in the access token
     * @param int $expires_in the time over which the access token will be valid,
     * in seconds, or {@link SimpleID\Protocols\OAuth\Token::TTL_PERPETUAL} if the token is not to expire
     * @param TokenGrantType $grant the grant, if any, from which the token is to be
     * generated
     * @param array<string, mixed> $additional additional data to be stored on the server for this
     * token
     * @return array<string, string> an array of parameters that can be included in the OAuth token
     * endpoint response
     */
    public function issueAccessToken($scope = [], $expires_in = Token::TTL_PERPETUAL, $grant = null, $additional = []) {
        $results = [];

        $token = AccessToken::create($this, $scope, $expires_in, $grant, $additional);

        $results['access_token'] = $token->getEncoded();
        $results['token_type'] = $token->getAccessTokenType();
        if ($expires_in != Token::TTL_PERPETUAL) $results['expires_in'] = strval($expires_in);

        return $results;
    }

    /**
     * Issues a refresh token.
     *
     * @param array<string> $scope the scope to be included in the access token
     * @param TokenGrantType $grant the grant, if any, from which the token is to be
     * generated
     * @param array<string, mixed> $additional additional data to be stored on the server for this
     * token
     * @return array<string, string> an array of parameters that can be included in the OAuth token
     * endpoint response
     */
    protected function issueRefreshToken($scope = [], $grant = NULL, $additional = []) {
        $token = RefreshToken::create($this, $scope, $grant, $additional);
        return [ 'refresh_token' => $token->getEncoded() ];
    }

    /**
     * Revokes all access and refresh tokens that were generated from
     * a particular grant.
     *
     * @param TokenGrantType $grant the grant
     * @return void
     */
    public function revokeTokensFromGrant($grant) {
        Token::revokeAll($this, $grant);
    }

    /**
     * Revokes all access and refresh tokens for this authorisation.
     *
     * @return void
     */
    public function revokeAllTokens() {
        Token::revokeAll($this);
    }

    /**
     * Returns the fully-qualified ID for this authorisation.
     *
     * The fully-qualified ID for an authorisation is the authorisation
     * state along with a hash of the owner and the client IDs.
     *
     * @return string the fully qualified ID
     */
    public function getFullyQualifiedID() {
        return $this->auth_state . self::AUTH_STATE_SEPARATOR . $this->id;
    }

    public function getStoreType() {
        return 'oauth';
    }

    public function getStoreID() {
        return $this->id;
    }

    public function setStoreID($id) {
        $this->id = $id;
    }

    /**
     * Builds a hash of the owner and client for identification
     * purposes
     *
     * @param Storable $owner the Storable object representing the resource
     * owner
     * @param Storable $client the Storable object representing the
     * client
     * @return string the hash
     */
    static public function buildID($owner, $client) {
        $owner_id = $owner->getStoreType() . ':' . $owner->getStoreID();
        $client_id = $client->getStoreType() . ':' . $client->getStoreID();
        
        $opaque = new OpaqueIdentifier();
        return $opaque->generate($owner_id . ':' . $client_id);
    }
}

?>