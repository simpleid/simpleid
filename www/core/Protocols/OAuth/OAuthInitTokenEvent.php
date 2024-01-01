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

namespace SimpleID\Protocols\OAuth;

use Psr\EventDispatcher\StoppableEventInterface;
use SimpleID\Protocols\OAuth\OAuthClient;
use SimpleID\Util\Events\BaseEvent;

/**
 * An event to authenticate an access token.
 * 
 * Listeners should conduct the necessary searches to look for and verify
 * the access token.  If successful, it should call
 * the {@link setToken()} method.
 */
class OAuthInitTokenEvent extends BaseEvent implements StoppableEventInterface {
    /** @var \SimpleID\Protocols\OAuth\AccessToken */
    protected $access_token = null;

    /**
     * Sets the access token.
     * 
     * Once this method is called, the event stops.
     * 
     * @param \SimpleID\Protocols\OAuth\AccessToken $access_token the access token
     * @return void
     */
    public function setToken(AccessToken $access_token) {
        $this->access_token = $access_token;
    }

    /**
     * Returns the access token set by the listeners.
     * 
     * @return \SimpleID\Protocols\OAuth\AccessToken the access token, or null
     */
    public function getToken() {
        return $this->access_token;
    }

    /**
     * Returns whether a access token has been set
     * 
     * @return bool true if a access token has been set
     */
    public function hasToken() {
        return ($this->access_token != null);
    }

    /**
     * {@inheritdoc}
     */
    public function isPropagationStopped(): bool {
        return ($this->access_token != null);
    }
}

?>