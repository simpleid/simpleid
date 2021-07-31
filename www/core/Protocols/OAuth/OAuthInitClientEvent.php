<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021
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

use Psr\EventDispatcher\StoppableEventInterface;
use SimpleID\Protocols\OAuth\OAuthClient;

/**
 * An event to authenticate a client.
 * 
 * Listeners should examine the request from the {@link getRequest()}
 * method for authentication credentials.  If this contains the
 * necessary credentials to authenticate a client, it should call
 * the {@link setClient()} method.
 */
class OAuthInitClientEvent implements StoppableEventInterface {
    protected $request;
    protected $client = null;
    protected $client_auth_method = null;

    public function __construct(Request $request) {
        $this->request = $request;
    }

    /**
     * Returns the OpenID request.
     * 
     * @return SimpleID\Protocols\OpenID\Request the OpenID request
     */
    public function getRequest() {
        return $this->request;
    }

    /**
     * Sets the authenticated client and the method used to authenticate
     * the client.
     * 
     * Once this method is called, the event stops.
     * 
     * @param SimpleID\Protocols\OAuth\OAuthClient $client the client authenticated
     * @param string $client_auth_method the authentication method used
     */
    public function setClient(OAuthClient $client, string $client_auth_method) {
        $this->client = $client;
    }

    /**
     * Returns the client set by the listeners.
     * 
     * @return SimpleID\Protocols\OAuth\OAuthClient the client, or null
     */
    public function getClient() {
        return $this->client;
    }

    /**
     * Returns whether a client has been set
     * 
     * @return bool true if a client has been set
     */
    public function hasClient() {
        return ($this->client != null);
    }

    /**
     * Returns the method used to authenticate the client.
     * 
     * @return string the authentication method, or null
     */
    public function getAuthMethod() {
        return $this->client_auth_method;
    }

    /**
     * {@inheritdoc}
     */
    public function isPropagationStopped(): bool {
        return ($this->client != null);
    }
}

?>