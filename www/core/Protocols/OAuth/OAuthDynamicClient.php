<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2022
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

use SimpleID\Protocols\HTTPResponse;
use SimpleID\Crypt\Random;

/**
 * A class representing an OAuth dynamic client.
 */
class OAuthDynamicClient extends OAuthClient {

    protected $dynamic = true;

    public function __construct($data = []) {
        parent::__construct($data);

        $rand = new Random();
        $this->cid = '_' . $rand->id() . '.oauth';
    }

    /**
     * Fetches the JSON web key set from the `jwks_uri` parameter.
     * 
     * @return void
     */
    public function fetchJWKs() {
        if (isset($this->container['oauth']['jwks_uri'])) {
            $web = \Web::instance();

            $response = new HTTPResponse($web->request($this->container['oauth']['jwks_uri'], [ 'headers' => [ 'Accept' => 'application/jwk-set+json,application/json,text/plain,application/octet-stream' ] ]));
            if ($response->isHttpError()) return;
        
            $jwks = json_decode($response->getBody(), true);
            if ($jwks == NULL) return;

            $this->container['oauth']['jwks'] = $jwks;
        }
    }

    /**
     * Returns the dynamic client's metadata.
     *
     * @return array<string, mixed> the dynamic client's metadata
     */
    public function getDynamicClientInfo() {
        $results = array_merge($this->container['oauth'], [
            'client_id' => $this->getStoreID()
        ]);

        // if jwk_uri exists, we delete jwks as we retreived this ourselves
        if (isset($results['jwk_uri'])) unset($results['jwks']);

        return $results;
    }
}

?>