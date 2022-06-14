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

namespace SimpleID\Protocols\OpenID;

use SimpleID\Protocols\ProtocolResult;

/**
 * An event trigger before an assertion response is sent, to allow
 * for modification.
 *
 * For positive assertions, listeners can assume that all user approvals
 * have been given and return a response array accordingly.  Where consent
 * is required, the response can be further modified through the
 * `openid_consent_form_submit` event.
 *
 * This hook will need to provide any aliases required.
 *
 * An example:
 *
 * ```php
 * $request = $event->getRequest();
 * $alias = $request->getAliasForExtension($my_uri);
 * $response['ns' . $alias] = $my_uri;
 * $response[$alias . '.field'] = 'value';
 * ```
 */
class OpenIDResponseBuildEvent {
    /** @var bool */
    protected $assertion;

    /** @var Request */
    protected $request;

    /** @var Response */
    protected $response;

    public function __construct(bool $assertion, Request $request, Response $response) {
        $this->assertion = $assertion;
        $this->request = $request;
        $this->response = $response;
    }

    /**
     * Returns whether a positive assertion response will be
     * made
     * 
     * @return bool true if a positive assertion is made, false otherwise
     */
    public function isPositiveAssertion() {
        return $this->assertion;
    }

    /**
     * Retrieves the OpenID request.
     * 
     * @return \SimpleID\Protocols\OpenID\Request the OpenID request
     */
    public function getRequest() {
        return $this->request;
    }

    /**
     * Retrieves the OpenID response.  This response can be
     * modified.
     * 
     * @return \SimpleID\Protocols\OpenID\Response the OpenID response to modify
     */
    public function getResponse() {
        return $this->response;
    }
}

?>