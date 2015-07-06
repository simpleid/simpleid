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

use SimpleID\Models\Client;

/**
 * A class representing an OAuth client.
 */
class OAuthClient extends Client {

    protected $dynamic = false;

    public function __construct($data) {
        parent::__construct(array_replace_recursive(array(
            'oauth' => array(
                'token_endpoint_auth_method' => 'client_secret_basic',
                'response_types' => array('code'),
                'grant_types' => array('authorization_code'),
                'application_type' => 'web'
            )
        ), $data));
    }

    /**
     * Returns whether a client is a confidential client.
     *
     * A client is a confidential client if a `client_secret` has been set,
     * and the `token_endpoint_auth_method` (if set) is not set to `none`.
     * This means that the client must authenticate with SimpleID using
     * credentials which the client is able to keep secret.
     *
     * @return bool true if the client is confidential
     */
    public function isConfidential() {
        if (isset($this->container['oauth']['token_endpoint_auth_method'])
            && ($this->container['oauth']['token_endpoint_auth_method'] == 'none'))
            return false;

        return (isset($this->container['oauth']['client_secret']));
    }

    /*public function getSectorIdentifier() {
        if (isset($this->container['connect']['sector_identifier_uri'])) {

        } elseif (isset($this->container['oauth']['redirect_uris'])) {

        } else {
            return $this->getStoreID();
        }
    }*/

}

?>