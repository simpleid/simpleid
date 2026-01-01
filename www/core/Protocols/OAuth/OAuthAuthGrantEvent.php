<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021-2026
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
 * An event triggered when an authorisation request has been granted.
 * 
 * Under an implicit flow, both this event and the {@link OAuthTokenGrantEvent} will be
 * triggered.
 * 
 */
class OAuthAuthGrantEvent extends OAuthEvent {
    /** @var Authorization */
    protected $authorization;

    /** @var array<string> */
    protected $scopes;

    /**
     * @param array<string> $scopes
     */
    public function __construct(Authorization $authorization, Request $request, Response $response, $scopes) {
        parent::__construct($request, $response);

        $this->authorization = $authorization;
        $this->scopes = $scopes;
    }

    /**
     * Returns the underlying authorisation object
     * 
     * @return Authorization the authorisation to
     * be granted
     */
    public function getAuthorization() {
        return $this->authorization;
    }

    /**
     * Returns the requested scope
     * 
     * @return array<string> the requested scope
     */
    public function getRequestedScope() {
        return $this->scopes;
    }
}

?>