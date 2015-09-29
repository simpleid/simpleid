<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2012
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

use SimpleID\Store\StoreManager;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Keys\SymmetricKey;
use \Web;
use \Base;

/**
 * Utility class to build a SimpleJWT key set based for a specified
 * client.
 *
 * Each of the methods in this class adds various keys to the key
 * set being built and returns an instance of this class to enable
 * chaining.  To obtain the final key set, call the {@link toKeySet()}
 * method.
 */
class KeySetBuilder {

    protected $set;
    protected $client;

    /**
     * Creates a key set builder for the specified client.
     *
     * @param SimpleID\Protocols\OAuth\OAuthClient the client
     */
    function __construct($client) {
        $this->set = new KeySet();
        $this->client = $client;
    }

    /**
     * Adds the client secret to the key set.
     *
     * @return KeySetBuilder
     */
    function addClientSecret() {
        $this->set->add(new SymmetricKey($client['oauth']['client_secret'], 'bin'));
        return $this;
    }

    /**
     * Adds the client's public keys.  This can be used to encrypt
     * data to the client.
     *
     * @return KeySetBuilder
     */
    function addClientPublicKeys() {
        if (!isset($client['oauth']['jwks']) && isset($client['oauth']['jwks_uri']) && is_subclass_of($client, 'SimpleID\Protocols\OAuth\OAuthDynamicClient')) {
            $client->fetchJWKs();
        }

        if (isset($client['oauth']['jwks'])) {
            $client_jwks = new KeySet();
            $client_jwks->load(json_encode($client['oauth']['jwks']));
            $this->set->addAll($client_jwks);
        }

        return $this;
    }

    /**
     * Adds the server's private keys.  This can be used to sign
     * data to the client.
     *
     * @return KeySetBuilder
     */
    function addServerPrivateKeys() {
        $f3 = Base::instance();
        $config = $f3->get('config');

        if (isset($config['private_jwks_file'])) {
            $server_jwks = new KeySet();
            $server_jwks->load(file_get_contents($config['private_jwks_file']));
            $this->set->addAll($server_jwks);
        }

        return $this;
    }

    /**
     * Adds the server's public keys.
     *
     * @return KeySetBuilder
     */
    function addServerPublicKeys() {
        $f3 = Base::instance();
        $config = $f3->get('config');

        if (isset($config['public_jwks_file'])) {
            $server_jwks = new KeySet();
            $server_jwks->load(file_get_contents($config['public_jwks_file']));
            $this->set->addAll($server_jwks);
        }

        return $this;
    }

    /**
     * Returns the completed key set.
     *
     * @return SimpleJWT\Keys\KeySet
     */
    function toKeySet() {
        return $this->set;
    }
}

?>
