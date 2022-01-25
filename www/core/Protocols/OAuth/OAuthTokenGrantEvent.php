<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021-2022
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


/**
 * An event triggered when an access token is being issued.
 *
 * This event is triggered at the authorisation endpoint (under implicit flow), or
 * at the token endpoint (under authorisation code or refresh token flows).
 *
 * Under an implicit flow, both this event and the {@link OAuthAuthGrantEvent} will be
 * triggered.
 * 
 */
class OAuthTokenGrantEvent extends OAuthAuthGrantEvent {
    protected $grant_type;

    public function __construct(string $grant_type, Authorization $authorization, Request $request, Response $response, $scopes) {
        parent::__construct($authorization, $request, $response, $scopes);

        $this->grant_type = $grant_type;
    }

    /**
     * Returns the grant type
     * 
     * @return string the grant type
     */
    public function getGrantType() {
        return $this->grant_type;
    }
}

?>