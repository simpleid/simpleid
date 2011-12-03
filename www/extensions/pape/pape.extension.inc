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

/** Namespaces for PAPE policies */
define('PAPE_POLICY_NONE', 'http://schemas.openid.net/pape/policies/2007/06/none');
define('PAPE_POLICY_PPID', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier');

/** Namespaces for PAPE levels */
define('PAPE_LEVEL_NIST800_63', 'http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf');

/**
 * Returns the support for PAPE in SimpleID XRDS document
 *
 * @return array
 * @see hook_xrds_types()
 */
function pape_xrds_types() {
    return array(
        OPENID_NS_PAPE,
        PAPE_POLICY_PPID,
        PAPE_LEVEL_NIST800_63
    );
}

/**
 * @see hook_checkid_identity()
 */
function pape_checkid_identity($request, $identity, $immediate) {
    global $user;
    
    // We only respond if the extension is requested
    if (!openid_extension_requested(OPENID_NS_PAPE, $request)) return null;
    
    // See if we are choosing an identity and save for later
    // This may be used by pape_response() to produce a private identifier
    if ($request['openid.identity'] == OPENID_IDENTIFIER_SELECT) _pape_identifier_select(true);
    
    $pape_request = openid_extension_filter_request(OPENID_NS_PAPE, $request);
        
    // If the relying party provides a max_auth_age
    if (isset($pape_request['max_auth_age'])) {
        // If we are not logged in then we don't need to do anything
        if ($user == NULL) return NULL;
        
        // If the last time we logged on actively (i.e. using a password) is greater than
        // max_auth_age, we then require the user to log in again
        if ((!isset($user['auth_active']) || !$user['auth_active']) 
            && ((time() - $user['auth_time']) > $pape_request['max_auth_age'])) {
            set_message('This web site\'s policy requires you to log in again to confirm your identity.');
            
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
    
    // Get what is requested
    $pape_request = openid_extension_filter_request(OPENID_NS_PAPE, $request);
        
    // If the extension is requested, we use the same alias, otherwise, we
    // make one up
    $alias = openid_extension_alias(OPENID_NS_PAPE, 'pape');
    $response = array();
    
    // The PAPE specification recommends us to respond even when the extension
    // is not present in the request.
    $response['openid.ns.' . $alias] = OPENID_NS_PAPE;
    
    // We return the last time the user logged in using the login form
    $response['openid.' . $alias . '.auth_time'] = gmstrftime('%Y-%m-%dT%H:%M:%SZ', $user['auth_time']);
    
    // We don't comply with NIST_SP800-63
    $response['openid.' . $alias . '.auth_level.ns.nist'] =  PAPE_LEVEL_NIST800_63;
    $response['openid.' . $alias . '.auth_level.nist'] = 0;

    // The default is that we don't apply any authentication policies. This can be changed later in the
    // function
    $response['openid.' . $alias . '.auth_policies'] = PAPE_POLICY_NONE;

    // Now we go through the authentication policies
    if (isset($pape_request['preferred_auth_policies'])) {
        $policies = preg_split('/\s+/', $pape_request['preferred_auth_policies']);
        
        if (in_array(PAPE_POLICY_PPID, $policies)) {
            // We want a ppid.  Check that the authentication request is correct
            if (_pape_identifier_select()) {
                $realm = openid_get_realm($request, $version);
                $identity = $request['openid.identity'];
                
                $ppid = _pape_ppid($identity, $realm);                
                $response['openid.claimed_id'] = $ppid;
                $response['openid.identity'] = $ppid;
            }
        }
    }
    
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

    if (isset($response['openid.ns.' . $alias])) $signed_fields[] = 'ns.' . $alias;
    foreach ($fields as $field) {
        if (isset($response['openid.' . $alias . '.' . $field])) $signed_fields[] = $alias . '.' . $field;
    }
    
    return $signed_fields;
}

/**
 * Sets and returns whether the current OpenID request is requesting an identity.
 *
 * @param bool $identifier_select
 * @return bool whether the current OpenID request is requesting an identity
 */
function _pape_identifier_select($identifier_select = NULL) {
    static $static_identifier_select = false;
    
    if (!is_null($identifier_select)) $static_identifier_select = $identifier_select;
    
    return $static_identifier_select;
}

/**
 * Generates a private personal identifier (PPID).  The PPID is an opaque identifier
 * for a particular user-RP pair
 *
 * @param string $identity the identity of the user
 * @param string $realm the URL of the relying party
 * @return string the PPID
 */
function _pape_ppid($identity, $realm) {
    // We are reusing the site-token from get_form_token() in common.inc
    if (store_get('site-token') == NULL) {
        $site_token = mt_rand();
        store_set('site-token', $site_token);
    } else {
        $site_token = store_get('site-token');
    }
    
    $parts = parse_url($realm);
    $host = $parts['host'];
    if (strstr($host, 'www.') === 0) $host = substr($host, 4);
    
    return simpleid_url('ppid/' . md5($site_token . $identity . $host));
}

?>
