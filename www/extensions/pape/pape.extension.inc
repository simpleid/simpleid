<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2009
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
 * Implements the Provider Authentication Policy Extension extension.
 * 
 *
 * @package simpleid
 * @subpackage extensions
 * @filesource
 */

/** Namespace for the PAPE extension */
define('OPENID_NS_PAPE', 'http://specs.openid.net/extensions/pape/1.0');

/**
 * Returns the support for PAPE in SimpleID XRDS document
 *
 * @return array
 * @see hook_xrds_types()
 */
function pape_xrds_types() {
    return array(
        OPENID_NS_PAPE,
        'http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf'
    );
}

/**
 * @see hook_checkid_identity()
 */
function pape_checkid_identity($request, $immediate) {
    global $user;
    
    // We only respond if the extension is requested
    if (!openid_extension_requested(OPENID_NS_PAPE, $request)) return null;
    
    $request = openid_extension_filter_request(OPENID_NS_PAPE, $request);
    
    // If the relying party provides a max_auth_age
    if (isset($request['max_auth_age'])) {
        // If we are not logged in then we don't need to do anything
        if ($user == NULL) return NULL;
        
        // If the last time we logged on manually is greater than
        // max_auth_age, we then require the user to log in again
        if ((time() - $user['auth_time']) > $request['max_auth_age']) {
            _user_logout();
            return CHECKID_LOGIN_REQUIRED;
        }
    }
}

/**
 * @see hook_response()
 */
function pape_response($assertion, $request) {
    global $user, $version;
    
    // We only deal with positive assertions
    if (!$assertion) return array();
    
    // We only respond if we are using OpenID 2 or later
    if ($version < OPENID_VERSION_2) return array();
    
    // The PAPE specification recommends us to respond even when the extension
    // is not present in the request.
    
    // If the extension is requested, we use the same alias, otherwise, we
    // make one up
    $alias = openid_extension_alias(OPENID_NS_PAPE, 'pape');
    $response = array();
    
    $response['openid.ns.' . $alias] = OPENID_NS_PAPE;
    
    // We return the last time the user logged in using the login form
    $response['openid.' . $alias . '.auth_time'] = gmstrftime('%Y-%m-%dT%H:%M:%SZ', $user['auth_time']);
    
    // We don't comply with NIST_SP800-63
    $response['openid.' . $alias . '.auth_level.ns.nist'] = 'http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf';
    $response['openid.' . $alias . '.auth_level.nist'] = 0;

    // We don't have any authentication policies
    $response['openid.' . $alias . '.auth_policies'] = 'http://schemas.openid.net/pape/policies/2007/06/none';
    
    return $response;
}

/**
 * Returns an array of fields that need signing.
 *
 * @see hook_signed_fields()
 */
function pape_signed_fields($response) {
    $fields = array_keys(openid_extension_filter_request(OPENID_NS_PAPE, $response));
    $alias = openid_extension_alias(OPENID_NS_PAPE);
    $signed_fields = array();

    foreach ($fields as $field) {
        if (isset($response['openid.' . $alias . '.' . $field])) $signed_fields[] = $alias . '.' . $field;
    }
    
    return $signed_fields;
}


?>
