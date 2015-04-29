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
 * $Id$
 */

/**
 * Authentication using a SSL client certificate.
 *
 * @package simpleid
 * @subpackage extensions
 * @filesource
 */
 

/**
 * Attempt to login using a SSL client certificate.
 *
 * Note that the web server must be set up to request a SSL client certificate
 * and pass the certificate's details to PHP.
 */
function certauth_user_auto_login()
{
    if (!_certauth_has_client_cert()) {
        return null;
    }
    
    $cert = trim($_SERVER['SSL_CLIENT_M_SERIAL']) . ';' . trim($_SERVER['SSL_CLIENT_I_DN']);
    log_debug('Client SSL certificate: ' . $cert);

    $uid = store_get_uid_from_cert($cert);
    if ($uid != null) {
        log_debug('Client SSL certificate accepted for ' . $uid);
        return user_load($uid);
    } else {
        log_warn('Client SSL certificate presented, but no user with that certificate exists.');
        return null;
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
function _certauth_has_client_cert()
{
    // False if we are not in HTTP
    if (!is_https()) {
        return false;
    }
    
    // False if certificate is not valid
    if (!isset($_SERVER['SSL_CLIENT_VERIFY']) || ($_SERVER['SSL_CLIENT_VERIFY'] !== 'SUCCESS')) {
        return false;
    }
    
    // False if certificate is expired or has no expiry date
    if (!isset($_SERVER['SSL_CLIENT_V_REMAIN']) || ($_SERVER['SSL_CLIENT_V_REMAIN'] < 0)) {
        return false;
    }
    if (!isset($_SERVER['SSL_CLIENT_V_END'])) {
        return false;
    }
    
    // False if no serial number
    if (!isset($_SERVER['SSL_CLIENT_M_SERIAL'])) {
        return false;
    }
    
    // False if no issuer
    if (!isset($_SERVER['SSL_CLIENT_I_DN'])) {
        return false;
    }
    
    return true;
}
