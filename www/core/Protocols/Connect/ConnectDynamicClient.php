<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2023
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

use SimpleID\Protocols\OAuth\OAuthDynamicClient;

/**
 * A class representing an OpenID Connect dynamic client.
 */
class ConnectDynamicClient extends OAuthDynamicClient {

    public function __construct($data = []) {
        parent::__construct(array_replace_recursive([
            'connect' => [
                'id_token_signed_response_alg' => 'RS256',
                'require_auth_time' => false,
            ]
        ], $data));
    }

    public function getDynamicClientInfo() {
        $results = array_merge(parent::getDynamicClientInfo(), $this->container['connect']);
        return $results;
    }
}

?>