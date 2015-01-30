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

namespace SimpleID\Protocols\OpenID;

use SimpleID\Protocols\XRDS\XRDSDiscovery;
use SimpleID\Models\Client;

class RelyingParty extends Client {

    // OpenID clients are always dynamic
    protected $dynamic = true;

    protected $realm;
    protected $services;

    public $return_to_verified;

    public function __construct($realm) {
        //parent::__construct();
        $this->realm = $realm;
    }

    /**
     * Returns the realm
     */
    public function getRealm() {
        return $this->realm;
    }

    public function getServices() {
        return $this->services;
    }

    public function discover() {
        $discovery = XRDSDiscovery::instance();
        $url = self::getDiscoveryURL($this->realm);
        $this->services = $discovery->discover($url);
    }

    /**
     * Returns the URL of a relying party endpoint for a specified realm.  This URL
     * is used to discover services associated with the realm.
     *
     * If the realm's domain contains the wild-card characters "*.", this is substituted
     * with "www.".
     *
     * @param string $realm the realm
     * @url string the URL
     *
     * @since 0.7
     */
    public static function getDiscoveryURL($realm) {
        $parts = parse_url($realm);
        $host = strtr($parts['host'], array('*.' => 'www.'));;
        
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

    public function getDisplayName() {
        
    }
}

?>