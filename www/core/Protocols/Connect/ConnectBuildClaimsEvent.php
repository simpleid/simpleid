<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021-2024
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

use SimpleID\Models\Client;
use SimpleID\Models\User;
use SimpleID\Util\Events\BaseDataCollectionEvent;

/**
 * Event to collect a set of claims to be included in an ID token or UserInfo response
 *
 */
class ConnectBuildClaimsEvent extends BaseDataCollectionEvent {
    /** @var User */
    protected $user;

    /** @var Client */
    protected $client;

    /** @var string */
    protected $context;

    /** @var array<string> */
    protected $scope;

    /** @var array<string, mixed>|null */
    protected $claims_requested;

    /**
     * @param User $user
     * @param Client $client
     * @param string $context
     * @param array<string> $scope
     * @param array<string, mixed>|null $claims_requested
     */
    public function __construct(User $user, Client $client, $context, $scope, $claims_requested = NULL) {
        parent::__construct();

        $this->user = $user;
        $this->client = $client;
        $this->context = $context;
        $this->scope = $scope;
        $this->claims_requested = $claims_requested;
    }

    /**
     * Returns the user about which the ID token is created
     * 
     * @return User the user about which the ID
     * token is created
     */
    public function getUser() {
        return $this->user;
    }

    /**
     * Returns the client to which the ID token will be
     * sent.
     * 
     * @return Client the client to which the
     * ID token will be sent
     */
    public function getClient() {
        return $this->client;
    }

    /**
     * Returns the context.
     * 
     * This is either `id_token` or `userinfo`
     * 
     * @return string the context
     */
    public function getContext() {
        return $this->context;
    }

    /**
     * Returns the scope for the response.
     * 
     * @return array<string> the scope
     */
    public function getScope() {
        return $this->scope;
    }

    /**
     * Returns the specific claims requested, if any
     * 
     * @return array<string, mixed>|null an array of claims or null
     */
    public function getRequestedClaims() {
        return $this->claims_requested;
    }
}

?>