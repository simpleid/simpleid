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

namespace SimpleID\Protocols\OpenID;

/**
 * Class representing an OpenID request.
 */
class Request extends Message {

    /**
     * Constant for the OP-local identifier which indicates that SimpleID should choose an identifier
     *
     * @link http://openid.net/specs/openid-authentication-2_0.html#anchor27
     */
    const OPENID_IDENTIFIER_SELECT = 'http://specs.openid.net/auth/2.0/identifier_select';

    /**
     * Constructs a new OpenID request.
     *
     * @param array<string, string> $request the request in array form
     */
    public function __construct($request) {
        $this->container = $request;

        foreach ($request as $key => $value) {
            if (strpos($key, 'openid.ns.') === 0) {
                $alias = substr($key, 10);
                $this->extension_map[$value] = $alias;
            }
        }

        if (!isset($this->container['openid.ns'])) {
            $this->version = Message::OPENID_VERSION_1_1;
        } elseif ($this->container['openid.ns'] != Message::OPENID_NS_2_0) {
            $this->version = Message::OPENID_VERSION_1_1;
        } else {
            $this->version = Message::OPENID_VERSION_2;
        }
    }

    /**
     * Gets the realm from the OpenID request.  This is specified differently
     * depending on the OpenID version.
     *
     * @return string the realm URI
     */
    public function getRealm() {
        $version = $this->getVersion();

        if ($version == Message::OPENID_VERSION_1_1) {
            $realm = $this->container['openid.trust_root'];
        }

        if ($version == Message::OPENID_VERSION_2) {
            $realm = $this->container['openid.realm'];
        }
        
        if (!isset($realm)) {
            $realm = $this->container['openid.return_to'];
        }
        
        return $realm;
    }

    /**
     * Determines whether the openid.return_to address matches a realm.
     *
     * A URL matches a realm if:
     *
     * 1. The URL scheme and port of the URL are identical to those in the realm.
     *    See RFC 3986, section 3.1 for rules about URI matching.
     * 2. The URL's path is equal to or a sub-directory of the realm's path.
     * 3. Either:
     *    (a) The realm's domain contains the wild-card characters "*.", and the
     *        trailing part of the URL's domain is identical to the part of the
     *        realm following the "*." wildcard, or
     *    (b) The URL's domain is identical to the realm's domain
     *
     * @param string $realm the realm
     * @param bool $strict whether the scheme also needs to match
     * @return bool true if the URL matches the realm
     * @since 0.6
     */
    function returnToMatches($realm, $strict = true) {
        $url = parse_url($this->container['openid.return_to']);
        $realm = parse_url($realm);
        if ($url == false) return false;
        if ($realm == false) return false;
        
        foreach(['user', 'pass', 'fragment'] as $key) {
            if (array_key_exists($key, $url) || array_key_exists($key, $realm))
                return false;
        }
        
        if ($url['scheme'] != $realm['scheme']) {
            if ($strict) return false;
            if ($url['scheme'] != 'https') return false;
            if ($realm['scheme'] != 'http') return false;
        }
        
        if (!isset($url['port']))
            $url['port'] = '';
        if (!isset($realm['port']))
            $realm['port'] = '';
        if (($url['port'] != $realm['port']))
            return false;

        if (!isset($url['host']))
            $url['host'] = '';
        if (!isset($realm['host']))
            $realm['host'] = '';

        $realm['host'] = strval($realm['host']);
        if (substr($realm['host'], 0, 2) == '*.') {
            $realm_re = '/^([^.]+\.)?' . preg_quote(substr($realm['host'], 2)) . '$/i';
        } else {
            $realm_re = '/^' . preg_quote($realm['host']) . '$/i';
        }
        
        $url['host'] = strval($url['host']);
        if (!preg_match($realm_re, $url['host'])) return false;
        
        if (!isset($url['path'])) {
            $url['path'] = '';
        } else {
            $url['path'] = strval($url['path']);
        }
        if (!isset($realm['path'])) {
            $realm['path'] = '';
        } else {
            $realm['path'] = strval($realm['path']);
        }
        if (substr($realm['path'], -1) == '/') $realm['path'] = substr($realm['path'], 0, -1);
        if (($url['path'] != $realm['path']) && !preg_match('#^' . preg_quote($realm['path']) . '/.*$#', $url['path'])) return false;
        
        return true;
    }

    /**
     * Calculates the base string from which an OpenID signature is generated.
     *
     * @return string|null the signature base string
     * @link http://openid.net/specs/openid-authentication-2_0.html#anchor11
     */
    public function getSignatureBaseString() {
        if (!isset($this->container['openid.signed'])) return null;
        $signed_fields = explode(',', $this->container['openid.signed']);
        return $this->buildSignatureBaseString($signed_fields, 'openid.');
    }

    /**
     * Returns the base string from which an OpenID signature is generated
     *
     * @return string the base string
     */
    protected function getPrefix() {
        return 'openid.';
    }

    /**
     * Returns a string representation of the request.
     *
     * @return string
     */
    public function toString() {
        return str_replace(array('+', '%7E'), array('%20', '~'), http_build_query($this->container));
    }
}

?>