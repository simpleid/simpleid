<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2024
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
    /** @var bool */
    protected $dynamic = false;

    /**
     * Creates a new OAuth client
     * 
     * @param array<string, mixed> $data
     */
    public function __construct($data) {
        parent::__construct(array_replace_recursive([
            'oauth' => [
                'token_endpoint_auth_method' => 'client_secret_basic',
                'response_types' => [ 'code' ],
                'grant_types' => [ 'authorization_code' ],
                'application_type' => 'web'
            ]
        ], $data));
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

    /**
     * Returns whether a specified redirect_uri has been registered
     * with the client.
     * 
     * @param string $redirect_uri the redirect_uri to test
     * @return bool true if the redirect_uri has been registered
     */
    public function hasRedirectUri($redirect_uri) {
        $redirect_uri_found = false;
        
        $is_native = (isset($this->container['oauth']['application_type'])) ? ($this->container['oauth']['application_type'] == 'native') : false;

        $redirect_uri_components = parse_url($redirect_uri);
        if ($redirect_uri_components == false) return false;

        foreach ($this->container['oauth']['redirect_uris'] as $client_redirect_uri) {
            $client_redirect_uri_components = parse_url($client_redirect_uri);
            if (($client_redirect_uri_components == false)
                || !isset($client_redirect_uri_components['scheme'])
                || !isset($client_redirect_uri_components['host'])) continue;

            // Quick check - if redirect_uri has a query component and the registered
            // one does not
            if (!isset($client_redirect_uri_components['query']) && isset($redirect_uri_components['query'])) continue;

            if ($is_native && ($client_redirect_uri_components['scheme'] == 'http')
                && (($client_redirect_uri_components['host'] == '127.0.0.1') || ($client_redirect_uri_components['host'] == '[::1]'))) {
                // For native applications with http loopback, we remove the port number
                // before making the comparison
                $request_redirect_uri = preg_replace('!(http://(127\.0\.0\.1|\[::1\]))(:\d+)?!', '$1', $redirect_uri);
            } else {
                $request_redirect_uri = $redirect_uri;
            }

            if (strcasecmp(substr($request_redirect_uri, 0, strlen($client_redirect_uri)), $client_redirect_uri) === 0) {
                $redirect_uri_found = true;
                break;
            }
        }

        return $redirect_uri_found;
    }
}

?>