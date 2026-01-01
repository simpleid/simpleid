<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2026
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

use SimpleID\Protocols\XRDS\XRDSDiscovery;
use SimpleID\Models\Client;

/**
 * A class representing an OpenID ID relying party.
 *
 * A relying party is identified based by its discovery URL.  The
 * discovery URL is based on the `openid.realm` parameter, with
 * the asterisk replaced by `www.`.
 */
class RelyingParty extends Client {

    // OpenID clients are always dynamic
    /** @var bool */
    protected $dynamic = true;

    /** @var string */
    private $store_id;

    /**
     * @param string $realm
     */
    public function __construct($realm) {
        parent::__construct([
            'openid' => [ 'realm' => $realm, 'services' => NULL, 'discovery_time' => 0 ]
        ]);
        $this->cid = $realm;
        $this->store_id = self::buildID($realm);
    }

    /**
     * Returns the realm
     *
     * @return string the realm
     */
    public function getRealm() {
        return $this->container['openid']['realm'];
    }

    /**
     * Returns the discovered XRDS services.
     *
     * Note that these discovered services may not be current.  The time
     * discovery was last made can be obtained from {@link getDiscoveryTime()}.
     *
     * @return \SimpleID\Protocols\XRDS\XRDSServices the XRDS services or null
     */
    public function getServices() {
        return $this->container['openid']['services'];
    }

    /**
     * Returns the time when discovery was most recently performed.
     *
     * @return int the time, or 0 if discovery was never performed for this
     * relying party
     */
    public function getDiscoveryTime() {
        return $this->container['openid']['discovery_time'];
    }

    /**
     * Performs XRDS discovery on this relying party.
     * 
     * @return void
     */
    public function discover() {
        $discovery = XRDSDiscovery::instance();
        $url = self::getDiscoveryURL($this->getRealm());
        $this->container['openid']['services'] = $discovery->discover($url);
    }

    /**
     * Returns the URL of a relying party endpoint for a specified realm.  This URL
     * is used to discover services associated with the realm.
     *
     * If the realm's domain contains the wild-card characters "*.", this is substituted
     * with "www.".
     *
     * @param string $realm the realm
     * @return string the URL
     *
     * @since 0.7
     */
    protected static function getDiscoveryURL($realm) {
        $parts = parse_url($realm);
        if ($parts == false) return $realm;
        $host = strtr($parts['host'], [ '*.' => 'www.' ]);
        
        $url = $parts['scheme'] . '://';
        if (isset($parts['user'])) {
            $url .= $parts['user'];
            if (isset($parts['pass'])) $url .= ':' . $parts['pass'];
            $url .= '@';
        }
        $url .= $host;
        if (isset($parts['port'])) $url .= ':' . $parts['port'];
        if (isset($parts['path'])) $url .= $parts['path'];
        if (isset($parts['query'])) $url .= '?' . $parts['query'];
        if (isset($parts['fragment'])) $url .= '#' . $parts['fragment'];
        return $url;
    }

    /**
     * @param string $realm
     * @return string
     */
    public static function buildID($realm) {
        $url = self::getDiscoveryURL($realm);
        return '_' . trim(strtr(base64_encode(sha1($url, true)), '+/', '-_'), '=') . '.openid';
    }

    public function getStoreID() {
        return $this->store_id;
    }

    public function setStoreID($id) {
        $this->store_id = $id;
    }

    public function getDisplayName() {
        return preg_replace('@^https?://(www\.|\*\.)?@', '', $this->getRealm());
    }

    public function getDisplayHTML() {
        return preg_replace('@^https?://(www\.|\*\.)?@', '<span class="url-elide">$0</span>', $this->getRealm());
    }
}

?>