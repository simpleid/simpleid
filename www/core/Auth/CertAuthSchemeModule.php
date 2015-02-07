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

namespace SimpleID\Auth;

use Psr\Log\LogLevel;
use SimpleID\Store\StoreManager;

/**
 * An authentication scheme that provides automatic authentication
 * via a client certificate.
 */
class CertAuthSchemeModule extends AuthSchemeModule {
    /**
     * Attempts to automatically login using the client certificate
     * 
     * @return SimpleID\Models\User the user object, or NULL
     */
    public function autoAuthHook() {
        if (!$this->hasClientCert()) return NULL;

        $cert = trim($_SERVER['SSL_CLIENT_M_SERIAL']) . ';' . trim($_SERVER['SSL_CLIENT_I_DN']);
        $this->logger->log(LogLevel::DEBUG, 'Client SSL certificate: ' . $cert);

        $store = StoreManager::instance();
        $user = $store->findUser('cert.certs', $cert);
        if ($user != NULL) {
            $this->logger->log(LogLevel::DEBUG, 'Client SSL certificate accepted for ' . $user['uid']);
            return $user;            
        } else {
            $this->logger->log(LogLevel::DEBUG, 'Client SSL certificate presented, but no user with that certificate exists.');
            return NULL;
        }
    }

    /**
     * Determines whether the user agent supplied valid a certificate identifying the
     * user.
     *
     * A valid certificate is supplied if all of the following occurs:
     *
     * - the connection is done using HTTPS (i.e. {@link is_https()} is true)
     * - the web server has been set up to request a certificate from the user agent
     * - the web server has been set up to pass the certificate details to PHP
     * - the certificate has not been revoked
     * - the certificate contains a serial number and a valid issuer
     *
     * @return true if the user agent has supplied a valid SSL certificate
     */
    protected function hasClientCert() {
        // False if we are not in HTTP
        if (!$this->isHttps()) return false;
        
        // False if certificate is not valid
        if (!isset($_SERVER['SSL_CLIENT_VERIFY']) || ($_SERVER['SSL_CLIENT_VERIFY'] !== 'SUCCESS')) return false;
        
        // False if certificate is expired or has no expiry date
        if (!isset($_SERVER['SSL_CLIENT_V_REMAIN']) || ($_SERVER['SSL_CLIENT_V_REMAIN'] < 0)) return false;
        if (!isset($_SERVER['SSL_CLIENT_V_END'])) return false;
        
        // False if no serial number
        if (!isset($_SERVER['SSL_CLIENT_M_SERIAL'])) return false;
        
        // False if no issuer
        if (!isset($_SERVER['SSL_CLIENT_I_DN'])) return false;
        
        return true;
    }
}
?>
