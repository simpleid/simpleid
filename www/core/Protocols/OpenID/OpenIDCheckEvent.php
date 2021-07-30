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

namespace SimpleID\Protocols\OpenID;

use SimpleID\Protocols\ProtocolResult;

/**
 * An event to process an OpenID authentication request.
 * 
 * There are two kinds of OpenID authentication requests:
 * 
 * - **Identifier requests.**  These are standard authentication requests
 *   provided by the OpenID specifications.  SimpleID processes these
 *   using the {@link SimpleID\Protocols\OpenID\OpenIDModule::openIDCheckIdentity()}
 *   methods, but listeners can modify the assertion result.
 * - **Extension requests**  The OpenID specifications also provides a mechanism
 *   for extensions to process authentication requests that are not about an identifier.
 * 
 * Listeners can identify whether a request is an identifier request or an extension
 * request by calling the {@link isExtensionRequest()} method.
 * 
 * Listeners can examine the contents of the request, and whether a request
 * is immediate (i.e. whether `openid.mode` is `checkid_immediate`) using
 * the {@link getRequest()} and {@link isImmediate()} methods respectively.
 * 
 * For identifier requests, the identifier that is subject to the request can
 * be obtained from the {@link getRequestedIdentity()} method.
 * 
 * The assertion result can be set using the {@link setResult()} method.
 * The result must be one of the constants defined in
 * {@link SimpleID\Protocols\ProtocolResult}.
 * 
 */
class OpenIDCheckEvent implements ProtocolResult {
    protected $request;
    protected $immediate;
    protected $identity = null;
    protected $result = null;

    public function __construct(Request $request, bool $immediate, ?string $identity = null) {
        $this->request = $request;
        $this->immediate = $immediate;
        $this->identity = $identity;
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
     * Returns whether the request is immediate
     * (i.e. whether `openid.mode` is `checkid_immediate`) 
     * 
     * @return bool true if the request is immediate
     */
    public function isImmediate() {
        return $this->immediate;
    }

    /**
     * Returns whether the request is an extension request.
     * If the request is not an extension request, it is a standard
     * identifier request.
     * 
     * @return bool true if the request is an extension request
     */
    public function isExtensionRequest() {
        return ($this->identity == null);
    }

    /**
     * Returns the identifier that is subject to the request.
     * If the request is an extension request, this method returns
     * null
     * 
     * @return string the OpenID identifier
     */
    public function getRequestedIdentity() {
        return $this->identity;
    }

    /**
     * Sets the assertion result.
     * 
     * This method is ignored if the provided assertion result
     * is *not worse* (i.e. greater than) the existing assertion
     * result stored in the event.
     * 
     * The result must be one of the constants defined in
     * {@link SimpleID\Protocols\ProtocolResult}.
     * 
     * @param int $result the assertion result
     */
    public function setResult(int $result) {
        if ($this->result == null) {
            $this->result = $result;
        } else {
            $this->result = min($this->result, $result);
        }
    }

    /**
     * Returns the currently stored assertion result.
     * 
     * If there is no assertion result currently stored
     * (i.e. {@link hasResult()} returns false), this
     * returns {@link SimpleID\Protocols\ProtocolResult::CHECKID_PROTOCOL_ERROR}.
     * 
     * Note that for identifier requests, the standard processing
     * (by {@link SimpleID\Protocols\OpenID\OpenIDModule::openIDCheckIdentity()})
     * occurs *after* these listeners are called.  Therefore, for these
     * requests, this function will return CHECKID_PROTOCOL_ERROR.
     * 
     * @return bool true if an assertion result has been set previously
     */
    public function getResult() {
        return ($this->result != null) ? $this->result : self::CHECKID_PROTOCOL_ERROR;
    }

    /**
     * Returns true if an assertion result has been set previously
     * by another listener.
     * 
     * Note that for identifier requests, the standard processing
     * (by {@link SimpleID\Protocols\OpenID\OpenIDModule::openIDCheckIdentity()})
     * occurs *after* these listeners are called.  Therefore, for these
     * requests, this function will return false.
     * 
     * @return bool true if an assertion result has been set previously
     */
    public function hasResult() {
        return ($this->result == null);
    }
}

?>