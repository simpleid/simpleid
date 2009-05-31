<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007-8
 *
 * Includes code Drupal OpenID module (http://drupal.org/project/openid)
 * Rowan Kerr <rowan@standardinteractive.com>
 * James Walker <james@bryght.com>
 *
 * Copyright (C) Rowan Kerr and James Walker
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
 * Main SimpleID file.
 *
 * @package simpleid
 * @filesource
 */
 
include_once "version.inc";
include_once "config.inc";
include_once "config.default.inc";
include_once "common.inc";
include_once "simpleweb.inc";
include_once "openid.inc";
include_once "discovery.inc";
include_once "user.inc";
include_once "cache.inc";
include_once "filesystem.store.inc";

// Allow for PHP5 version of xtemplate
if (version_compare(PHP_VERSION, '5.0.0') === 1) {
    include "lib/xtemplate.class.php";
} else {
    include "lib/xtemplate-php4.class.php";
}


define('CACHE_DIR', SIMPLEID_CACHE_DIR);

define('CHECKID_RETURN_TO_SUSPECT', 3);
define('CHECKID_APPROVAL_REQUIRED', 2);
define('CHECKID_OK', 1);
define('CHECKID_LOGIN_REQUIRED', -1);
define('CHECKID_IDENTITIES_NOT_MATCHING', -2);
define('CHECKID_IDENTITY_NOT_EXIST', -3);
define('CHECKID_PROTOCOL_ERROR', -127);

define('CREATE_ASSOCIATION_STATELESS', 2);
define('CREATE_ASSOCIATION_DEFAULT', 1);


/**
 * This variable holds the version of the OpenID specification associated with
 * the current OpenID request.  This can be either {@link OPENID_VERSION_1_1}
 * or {@link OPENID_VERSION_2}.
 *
 * @global int $version
 */
$version = OPENID_VERSION_1_1;

/**
 * This variable holds an instance of the XTemplate engine.
 *
 * @global object $xtpl
 */
$xtpl = NULL;

simpleid_start();

/**
 * Entry point for SimpleID.
 *
 * @see user_init()
 */
function simpleid_start() {
    global $xtpl;
        
    $xtpl = new XTemplate('html/template.xtpl');
    $xtpl->assign('version', SIMPLEID_VERSION);
    
    // Check if the configuration file has been defined
    if (!defined('SIMPLEID_BASE_URL')) {
        set_message('No configuration file found.  See the <a href="http://simpleid.sourceforge.net/manual">manual</a> for instructions on how to set up a configuration file.');
        $xtpl->parse('main');
        $xtpl->out('main');
        exit;
    }
    
    if (!is_dir(SIMPLEID_IDENTITIES_DIR)) {
        set_message('Identities directory not found.  See the <a href="http://simpleid.sourceforge.net/manual">manual</a> for instructions on how to set up SimpleID.');
        $xtpl->parse('main');
        $xtpl->out('main');
        exit;
    }
    
    if (!is_dir(SIMPLEID_CACHE_DIR) || !is_writeable(SIMPLEID_CACHE_DIR)) {
        set_message('Cache directory not found or not writeable.  See the <a href="http://simpleid.sourceforge.net/manual">manual</a> for instructions on how to set up SimpleID.');
        $xtpl->parse('main');
        $xtpl->out('main');
        exit;
    }
    
    openid_fix_post($_REQUEST);
    
    $q = (isset($_REQUEST['q'])) ? $_REQUEST['q'] : '';
    $q = explode('/', $q);
    
    extension_init();
    user_init($q[0]);
    
    // Clean stale assocations
    cache_gc(SIMPLEID_ASSOC_EXPIRES_IN, 'association');
    
    $routes = array(
        'continue' => 'simpleid_continue',
        'send' => 'simpleid_send',
        'autorelease' => 'simpleid_autorelease',
        'openid' => 'simpleid_process_openid',
        'login' => 'user_login',
        'logout' => 'user_logout',
        'user' => 'user_public_page',
        'user/(.+)' => 'user_public_page',
        'discovery' => 'user_discovery',
        'xrds/(.*)' => 'user_xrds',
        'xrds' => 'simpleid_xrds',
        '.*' => 'simpleid_index'
    );
    $routes = array_merge($routes, extension_invoke_all('routes'));
    
    simpleweb_run($routes, implode('/', $q));
}

function simpleid_index() {
    header('Vary: Accept');
    if (isset($_REQUEST['openid.mode'])) {
        simpleid_process_openid($_REQUEST);
        return;
    } elseif (stristr($_SERVER['HTTP_ACCEPT'], 'application/xrds+xml')) {
        simpleid_xrds();
    } else {
        // Point to SimpleID's XRDS document
        header('X-XRDS-Location: ' . simpleid_url('q=xrds'));
        user_page();
    }
}

/**
 * Processes a user's preferences in relation to automatic verification of a
 * relying party.
 */
function simpleid_autorelease() {
    global $user;
    
    if ($user == NULL) {
        user_login_form('');
        return;
    }
    
    if (!validate_form_token($_POST['tk'], 'autorelease')) {
        set_message('SimpleID detected a potential security attack.  Please try again.');
        user_page();
        return;
    }

    $rps =& $user['rps'];
    
    if (isset($_POST['autorelease'])) {
        foreach ($_POST['autorelease'] as $realm => $autorelease) {
            if (isset($rps[$realm])) {
                $rps[$realm]['auto_release'] = ($autorelease) ? 1 : 0;
            }
        }
    }
    
    if (isset($_POST['remove'])) {
        foreach ($_POST['remove'] as $realm => $autorelease) {
            if (isset($rps[$realm])) {
                unset($rps[$realm]);
            }
        }
    }
    
    if (isset($_POST['update-all'])) {
        foreach ($rps as $realm => $rp) {
            $rps[$realm]['auto_release'] = (isset($_POST['autorelease'][$realm]) && $_POST['autorelease'][$realm]) ? 1 : 0;
        }
    }
    
    user_save($user);
    
    set_message('Your preferences have been saved.');
    user_page();
    
}

/**
 * Process an OpenID request.
 *
 * <p>This function determines the version of the OpenID specification that is
 * relevant to this request, checks openid.mode and passes the
 * request on to the function required to process the request.</p>
 *
 * @param mixed $request the OpenID request
 */
function simpleid_process_openid($request) {
    global $version;
    
    $version = openid_get_version($request);
    
    switch ($request['openid.mode']) {
        case 'associate':
            simpleid_associate($request);
            return;
        case 'checkid_immediate':
        case 'checkid_setup':
            return simpleid_checkid($request);
        case 'check_authentication':
            simpleid_authenticate($request);
            break;
        default:
            set_message('Invalid OpenID message.');
            user_page();
    }
}

/**
 * Processes an association request from a relying party.  [8]
 *
 * <p>An association request has an openid.mode value of
 * associate.  This function checks whether the association request
 * is valid, and if so, creates an association and sends the response to
 * the relying party.</p>
 *
 * @see _simpleid_create_association()
 * @param mixed $request the OpenID request
 *
 */
function simpleid_associate($request) {
    global $version;
    
    $assoc_types = openid_association_types();
    $session_types = openid_session_types($version);

    // Common Request Parameters [8.1.1]
    if (($version == OPENID_VERSION_1_1) && !isset($request['openid.session_type'])) $request['openid.session_type'] = '';
    $assoc_type = $request['openid.assoc_type'];
    $session_type = $request['openid.session_type'];
    
    // Diffie-Hellman Request Parameters [8.1.2]
    $dh_modulus = (isset($request['openid.dh_modulus'])) ? $request['openid.dh_modulus'] : NULL;
    $dh_gen = (isset($request['openid.dh_gen'])) ? $request['openid.dh_gen'] : NULL;
    $dh_consumer_public = $request['openid.dh_consumer_public'];
    
    if (!isset($request['openid.session_type']) || !isset($request['openid.assoc_type'])) {
        openid_direct_error('openid.session_type or openid.assoc_type not set');
        return;
    }
    
    // Check if the assoc_type is supported
    if (!array_key_exists($assoc_type, $assoc_types)) {
        $error = array(
            'error_code' => 'unsupported-type',
            'session_type' => 'DH-SHA1',
            'assoc_type' => 'HMAC-SHA1'
        );
        openid_direct_error('The association type is not supported by SimpleID.', $error, $version);
        return;
    }
    // Check if the assoc_type is supported
    if (!array_key_exists($session_type, $session_types)) {
        $error = array(
            'error_code' => 'unsupported-type',
            'session_type' => 'DH-SHA1',
            'assoc_type' => 'HMAC-SHA1'
        );
        openid_direct_error('The session type is not supported by SimpleID.', $error, $version);
        return;
    }
    
    if ($session_type == 'DH-SHA1' || $session_type == 'DH-SHA256') {
        if (!$dh_consumer_public) {
            openid_direct_error('openid.dh_consumer_public not set');
            return;
        }
    }

    $response = _simpleid_create_association(CREATE_ASSOCIATION_DEFAULT, $assoc_type, $session_type, $dh_modulus, $dh_gen, $dh_consumer_public);
    
    openid_direct_response(openid_direct_message($response, $version));
}


/**
 * Creates an association.
 *
 * @param int $mode either CREATE_ASSOCIATION_DEFAULT or CREATE_ASSOCIATION_STATELESS
 * @param string $assoc_type a valid OpenID association type
 * @param string $session_type a valid OpenID session type
 * @param string $dh_modulus for Diffie-Hellman key exchange, the modulus encoded in Base64
 * @param string $dh_gen for Diffie-Hellman key exchange, g encoded in Base64
 * @param string $dh_consumer_public for Diffie-Hellman key exchange, the public key of the relying party encoded in Base64
 * @return mixed if $mode is CREATE_ASSOCIATION_DEFAULT, an OpenID response
 * to the association request, if $mode is CREATE_ASSOCIATION_STATELESS, the
 * association data for storage.
 */
function _simpleid_create_association($mode = CREATE_ASSOCIATION_DEFAULT, $assoc_type = 'HMAC-SHA1', $session_type = 'no-encryption', $dh_modulus = NULL, $dh_gen = NULL, $dh_consumer_public = NULL) {
    global $version;
    
    $assoc_types = openid_association_types();
    $session_types = openid_session_types($version);
    
    $mac_size = $assoc_types[$assoc_type]['mac_size'];
    $hmac_func = $assoc_types[$assoc_type]['hmac_func'];
    
    $assoc_handle = dechex(intval(time())) . bin2hex(openid_random(4));
    $expires_in = SIMPLEID_ASSOC_EXPIRES_IN;
    
    $secret = openid_random($mac_size);
    
    $response = array(
        'assoc_handle' => $assoc_handle,
        'assoc_type' => $assoc_type,
        'expires_in' => $expires_in
    );
    
    // If $session_type is '', then it must be using OpenID 1.1 (blank parameter
    // is not allowed for OpenID 2.0.  For OpenID 1.1 blank requests, we don't
    // put a session_type in the response.
    if ($session_type != '') $response['session_type'] = $session_type;
    
    if (($session_type == 'no-encryption') || ($session_type == '')) {
        $mac_key = base64_encode(call_user_func($hmac_func, $secret, $response['assoc_handle']));
        $response['mac_key'] = $mac_key;
    } elseif ($session_type == 'DH-SHA1' || $session_type == 'DH-SHA256') {
        $hash_func = $session_types[$session_type]['hash_func'];
        
        $dh_assoc = openid_dh_server_assoc($secret, $dh_consumer_public, $dh_modulus, $dh_gen, $hash_func);
        $mac_key = base64_encode($secret);
        $response['dh_server_public'] = $dh_assoc['dh_server_public'];
        $response['enc_mac_key'] = $dh_assoc['enc_mac_key'];
    }

    $association = array('assoc_handle' => $assoc_handle, 'assoc_type' => $assoc_type, 'mac_key' => $mac_key, 'created' => time());
    if ($mode == CREATE_ASSOCIATION_STATELESS) $association['stateless'] = 1;
    cache_set('association', $assoc_handle, $association);

    if ($mode == CREATE_ASSOCIATION_DEFAULT) {
        return $response;
    } else {
        return $association;
    }
}




/**
 * Processes an autentication request from a relying party.
 *
 * <p>An association request has an openid.mode value of
 * checkid_setup or checkid_immediate.  This function calls
 * {@link _simpleid_checkid()} to see whether the user logged on into SimpleID
 * matches the identity supplied in the OpenID request.</p>
 *
 * <p>Depending on the OpenID version, this function will supply an appropriate
 * assertion.</p>
 *
 * @param mixed $request the OpenID request
 *
 */
function simpleid_checkid($request) {
    global $version;
    
    $immediate = ($request['openid.mode'] == 'checkid_immediate');

    // Check for protocol correctness    
    if ($version == OPENID_VERSION_1_1) {
        if (!isset($request['openid.return_to'])) {
            indirect_fatal_error('Protocol Error: openid.return_to not set.');
            return;
        }
        if (!isset($request['openid.identity'])) {
            indirect_fatal_error('Protocol Error: openid.identity not set.');
            return;
        }
    }

    if ($version == OPENID_VERSION_2) {
        if (isset($request['openid.identity']) && !isset($request['openid.claimed_id'])) {
            indirect_fatal_error('Protocol Error: openid.identity set, but not openid.claimed_id.');
            return;
        }
        
        if (!isset($request['openid.realm']) && !isset($request['openid.return_to'])) {
            indirect_fatal_error('Protocol Error: openid.return_to not set when openid.realm is not set.');
            return;
        }
    }
    
    if (isset($request['openid.return_to'])) {
        $realm = openid_get_realm($request, $version);
        
        if (!openid_url_matches_realm($request['openid.return_to'], $realm)) {
            openid_indirect_error($request['openid.return_to'], 'Protocol Error: openid.return_to does not match realm.');
            return;
        }
    }
    
    if (isset($request['openid.identity'])) {
        $result = _simpleid_checkid($request);
        
        switch ($result) {
            case CHECKID_APPROVAL_REQUIRED:
                if ($immediate) {
                    $response = simpleid_checkid_approval_required($request);
                    return redirect_form($request['openid.return_to'], $response);
                } else {
                    $response = simpleid_checkid_ok($request);
                    return simpleid_rp_form($request, $response);
                }
                break;
            case CHECKID_RETURN_TO_SUSPECT:
                if ($immediate) {
                    $response = simpleid_checkid_error($immediate);
                    return redirect_form($request['openid.return_to'], $response);
                } else {
                    $response = simpleid_checkid_ok($request);
                    return simpleid_rp_form($request, $response, CHECKID_RETURN_TO_SUSPECT);
                }
                break;
            case CHECKID_OK:
                $response = simpleid_checkid_ok($request);
                $response = simpleid_sign($response, $request['openid.assoc_handle']);
                return redirect_form($request['openid.return_to'], $response);
                break;
            case CHECKID_LOGIN_REQUIRED:
                if ($immediate) {
                    $response = simpleid_checkid_login_required($request);
                    return redirect_form($request['openid.return_to'], $response);
                } else {
                    user_login_form('continue', pickle($request));
                    exit;
                }
                break;
            case CHECKID_IDENTITIES_NOT_MATCHING:
            case CHECKID_IDENTITY_NOT_EXIST:
                $response = simpleid_checkid_error($immediate);
                if ($immediate) {                
                    return redirect_form($request['openid.return_to'], $response);
                } else {                
                    return simpleid_rp_form($request, $response);                
                }
                break;
            case CHECKID_PROTOCOL_ERROR:
                // Do nothing - error has already been sent
        }
    } else {
        extension_invoke_all('assert', $request);
    }
}

/**
 * Checks whether the current user logged into SimpleID matches the identity
 * supplied in an OpenID request.
 *
 * @param mixed &$request the OpenID request
 * @return int one of CHECKID_OK, CHECKID_APPROVAL_REQUIRED, CHECKID_RETURN_TO_SUSPECT, CHECKID_IDENTITY_NOT_EXIST,
 * CHECKID_IDENTITIES_NOT_MATCHING, CHECKID_LOGIN_REQUIRED or CHECKID_PROTOCOL_ERROR
 * @global array the current logged in user
 */
function _simpleid_checkid(&$request) {
    global $user, $version;
    
    $realm = openid_get_realm($request, $version);
    
    // Check 1: Is the user logged into SimpleID as any user?
    if ($user == NULL) {
        return CHECKID_LOGIN_REQUIRED;
    } else {
        $uid = $user['uid'];
    }
    
    // Check 2: Is the user logged in as the same identity as the identity requested?
    // Choose the identity URL for the user automatically
    if ($request['openid.identity'] == OPENID_IDENTIFIER_SELECT) {        
        $test_user = user_load($uid);
        $identity = $test_user['identity'];
        $request['openid.claimed_id'] = $identity;
        $request['openid.identity'] = $identity;
    } else {
        $identity = $request['openid.identity'];
        $test_user = user_load_from_identity($identity);
    }
    if ($test_user == NULL) return CHECKID_IDENTITY_NOT_EXIST;
    if ($test_user['uid'] != $user['uid']) {
        return CHECKID_IDENTITIES_NOT_MATCHING;
    }
    
    // Check 3: Discover the realm and match its return_to
    $rp = (isset($user['rp'][$realm])) ? $user['rp'][$realm] : NULL;
    
    if (($version == OPENID_VERSION_2) && SIMPLEID_VERIFY_RETURN_URL_USING_REALM) {
        $url = openid_realm_discovery_url($realm);
        $verified = FALSE;
        
        cache_gc(3600, 'rp-services');
        $services = cache_get('rp-services', $url);
        if ($services == NULL) {
            $services = discovery_get_services($url);
            cache_set('rp-services', $url, $services);
        }
        $services = discovery_get_service_by_type($services, OPENID_RETURN_TO);
        
        if ($services) {
            $return_to_uris = array();
            
            foreach ($services as $service) {
                $return_to_uris = array_merge($return_to_uris, $service['uri']);
            }
            foreach ($return_to_uris as $return_to) {
                if (openid_url_matches_realm($request['openid.return_to'], $return_to)) {
                    $verified = TRUE;
                    break;
                }
            }
        }
        
        if (!$verified) {
            return CHECKID_RETURN_TO_SUSPECT;
        }
    }
    
    // Check 4: For checkid_immediate, the user must already have given
    // permission to log in automatically.
    if (($rp != NULL) && ($rp['auto_release'] == 1)) {
        return CHECKID_OK;
    } else {
        return CHECKID_APPROVAL_REQUIRED;
    }
}

/**
 * Returns an OpenID response indicating a positive assertion.
 *
 * @param mixed $request the OpenID request
 * @return mixed an OpenID response with a positive assertion
 */
function simpleid_checkid_ok($request) {
    global $version;
    
    $message = array(
        'openid.mode' => 'id_res',
        'openid.op_endpoint' => simpleid_url(),
        'openid.identity' => $request['openid.identity'],
        'openid.return_to' => $request['openid.return_to'],
        'openid.response_nonce' => openid_nonce(),
    );
    
    if (isset($request['openid.assoc_handle'])) $message['openid.assoc_handle'] = $request['openid.assoc_handle'];
    
    if ($version == OPENID_VERSION_2) {
        $message['openid.claimed_id'] = $request['openid.claimed_id'];
    }
    
    $message = array_merge($message, extension_invoke_all('id_res', $request));
    
    return openid_indirect_message($message, $version);
}

/**
 * Returns an OpenID response indicating a negative assertion to a
 * checkid_immediate request, where an approval of the relying party by the
 * user is required  [10.2]
 *
 * @param mixed $request the OpenID request
 * @return mixed an OpenID response with a negative assertion
 */
function simpleid_checkid_approval_required($request) {
    global $version;
    
    if ($version == OPENID_VERSION_2) {
        $message = array('openid.mode' => 'setup_needed');
    } else {
        $request['openid.mode'] = 'checkid_setup';
        $message = array(
            'openid.mode' => 'id_res',            
            'openid.user_setup_url' => simpleid_url('q=continue&s=' . rawurlencode(pickle($request)))
        );
    }
    
    return openid_indirect_message($message, $version);
}

/**
 * Returns an OpenID response indicating a negative assertion to a
 * checkid_immediate request, where a login is required  [10.2]
 *
 * @param mixed $request the OpenID request
 * @return mixed an OpenID response with a negative assertion
 */
function simpleid_checkid_login_required($request) {
    global $version;
    
    if ($version == OPENID_VERSION_2) {
        $message = array('openid.mode' => 'setup_needed');
    } else {    
        $message = array(
            'openid.mode' => 'id_res',
            'openid.user_setup_url' => simpleid_url('q=login&destination=continue&s=' . rawurlencode(pickle($request)))
        );
    }
    
    return openid_indirect_message($message, $version);
}

/**
 * Returns an OpenID response indicating a negative assertion  [10.2]
 *
 * @param bool $immediate whether checkid_immediate was used
 * @return mixed an OpenID response with a negative assertion
 */
function simpleid_checkid_error($immediate) {
    global $version;
    
    $message = array();
    if ($immediate) {
        if ($version == OPENID_VERSION_2) {
            $message['openid.mode'] = 'setup_needed';
        } else {
            $message['openid.mode'] = 'id_res';
        }
    } else {
        $message['openid.mode'] = 'cancel';
    }
    return openid_indirect_message($message, $version);
}

/**
 * Signs an OpenID response, using signature information from an association
 * handle.
 *
 * @param array &$response the OpenID response
 * @param array $assoc_handle the association handle containing key information
 * for the signature.  If $assoc_handle is not specified, a stateless association
 * is created
 * @return array the signed OpenID response
 *
 */
function simpleid_sign(&$response, $assoc_handle = NULL) {
    if (!$assoc_handle) {
        $assoc = _simpleid_create_association(CREATE_ASSOCIATION_STATELESS);
        $response['openid.assoc_handle'] = $assoc['assoc_handle'];
    } else {
        $assoc = cache_get('association', $assoc_handle);
        
        if ($assoc['created'] + SIMPLEID_ASSOC_EXPIRES_IN < time()) {
            // Association has expired, need to create a new one
            $response['openid.invalidate_handle'] = $assoc_handle;
            $assoc = _simpleid_create_association(CREATE_ASSOCIATION_STATELESS);
            $response['openid.assoc_handle'] = $assoc['assoc_handle'];
        }
    }
    
    // Get all the signed fields [10.1]
    $signed_fields = array('op_endpoint', 'return_to', 'response_nonce', 'assoc_handle', 'identity', 'claimed_id');
    $signed_fields = array_merge($signed_fields, extension_invoke_all('signed_fields', $response));
    
    // Check if the signed keys are actually present
    $to_sign = array();
    foreach ($signed_fields as $field) {
        if (isset($response['openid.' . $field])) $to_sign[] = $field;
    }
    
    $response['openid.signed'] = implode(',', $to_sign);
  
    // Generate signature for this message
    $mac_key = $assoc['mac_key'];
    $assoc_types = openid_association_types();
    $hmac_func = $assoc_types[$assoc['assoc_type']]['hmac_func'];
    
    $response['openid.sig'] = openid_sign($response, $to_sign, $mac_key, $hmac_func);
    return $response;
}

/**
 * Verify signatures generated using stateless mode [11.4.2]
 *
 *
 * @param mixed $request the OpenID request 
 */
function simpleid_authenticate($request) {
    global $version;
    
    $is_valid = TRUE;
  
    $assoc = (isset($request['openid.assoc_handle'])) ? cache_get('association', $request['openid.assoc_handle']) : NULL;
  
    if (!$assoc || !$assoc['assoc_type']) {
        $is_valid = FALSE;
    } else {
        $mac_key = $assoc['mac_key'];
        $assoc_types = openid_association_types();
        $hmac_func = $assoc_types[$assoc['assoc_type']]['hmac_func'];
        
        $signed_keys = explode(',', $request['openid.signed']);
        $signature = openid_sign($request, $signed_keys, $mac_key, $hmac_func);
        if ($signature != $request['openid.sig']) $is_valid = FALSE;
    }

    if ($is_valid) {
        $response = array('is_valid' => 'true');
        if ($assoc['stateless']) {
            // Stateless association handles should be used once, thus we should invalidate this one.
            $response['invalidate_handle'] = $request['openid.assoc_handle'];
        }
    } else {
        $response = array('is_valid' => 'false');
    }
    
    // RP wants to check whether a handle is invalid
    if (isset($request['openid.invalidate_handle'])) {
        $invalid_assoc = cache_get('association', $request['openid.invalidate_handle']);
        
        if (!$invalid_assoc || ($invalid_assoc['created'] + SIMPLEID_ASSOC_EXPIRES_IN < time())) {
            // Yes, it's invalid
            $response['invalidate_handle'] = $request['openid.invalidate_handle'];
        }
    }

    openid_direct_response(openid_direct_message($response, $version));
}



/**
 * Continues an OpenID authentication request.
 *
 * <p>This function decodes an OpenID authentication request specified in the
 * s request parameter and feeds it to the
 * {@link simpleid_process_openid} function.  This allows SimpleID to preserve
 * the state of an OpenID request.</p>
 */
function simpleid_continue() {
    simpleid_process_openid(unpickle($_REQUEST['s']));
}

/**
 * Provides a form for user verification of a relying party, where the 
 * {@link _simpleid_checkid()} function returns a CHECKID_APPROVAL_REQUIRED
 *
 * @param mixed $request the original OpenID request
 * @param mixed $response the proposed OpenID response, subject to user
 * verification
 * @param int $reason either CHECKID_APPROVAL_REQUIRED or CHECKID_RETURN_TO_SUSPECT
 */
function simpleid_rp_form($request, $response, $reason = CHECKID_APPROVAL_REQUIRED) {
    global $user;
    global $xtpl;
    global $version;
    
    $request_state = pickle($request);
    
    user_block($request_state);

    $realm = openid_get_realm($request, $version);
    
    $xtpl->assign('token', get_form_token('rp'));
    $xtpl->assign('state', pickle($response));
    $xtpl->assign('realm', htmlspecialchars($realm, ENT_QUOTES, 'UTF-8'));

    if ($response['openid.mode'] == 'cancel') {
        $xtpl->assign('request_state', $request_state);
        $xtpl->assign('return_to', htmlspecialchars($request['openid.return_to'], ENT_QUOTES, 'UTF-8'));
        $xtpl->assign('identity', htmlspecialchars($request['openid.identity'], ENT_QUOTES, 'UTF-8'));
        $xtpl->parse('main.rp.cancel');
    } else {        
        $rp = (isset($user['rp'][$realm])) ? $user['rp'][$realm] : NULL;
        
        $extensions = extension_invoke_all('form', $request, $rp);
        $xtpl->assign('extensions', implode($extensions));
        
        if ($reason == CHECKID_RETURN_TO_SUSPECT) {
            $xtpl->parse('main.rp.setup.suspect');
        }
        $xtpl->parse('main.rp.setup');
    }
    
    $xtpl->parse('main.rp');
    
    $xtpl->assign('title', 'OpenID Login');
    $xtpl->assign('page_class', 'dialog-page');
    $xtpl->parse('main');
    
    $xtpl->out('main');
}


/**
 * Processes a user response from the {@link simpleid_rp_form()} function.
 *
 * <p>If the user verifies the relying party, an OpenID response will be sent to
 * the relying party.</p>
 *
 */
function simpleid_send() {
    global $user, $version;
    
    if ($user == NULL) {
        user_login_form('');
        return;
    }
    
    if (!validate_form_token($_REQUEST['tk'], 'rp')) {
        set_message('SimpleID detected a potential security attack.  Please try again.');
        $xtpl->assign('title', 'OpenID Login');
        $xtpl->parse('main');
        $xtpl->out('main');
        return;
    }
    
    $uid = $user['uid'];
    
    $response = unpickle($_REQUEST['s']);
    $version = openid_get_version($response);
    $return_to = $response['openid.return_to'];
    if (!$return_to) $return_to = $_REQUEST['openid.return_to'];
    
    extension_invoke_all('send', $response);
    
    if ($_REQUEST['op'] == 'Cancel') {
        $response = simpleid_checkid_error(false);
        if (!$return_to) set_message('Log in cancelled.');
    } else {
        $now = time();
        $realm = $_REQUEST['openid.realm'];
        
        if (isset($user['rp'][$realm])) {
            $rp = $user['rp'][$realm];
        } else {
            $rp = array('realm' => $realm, 'first_time' => $now);
        }
        $rp['last_time'] = $now;
        $rp['auto_release'] = (isset($_REQUEST['autorelease']) && $_REQUEST['autorelease']) ? 1 : 0;
        
        $user['rp'][$realm] = $rp;
        user_save($user);
        
        $response = simpleid_sign($response, $response['openid.assoc_handle']);
        if (!$return_to) set_message('You were logged in successfully.');
    }

    if ($return_to) {
        redirect_form($return_to, $response);
    } else {
        user_page();
    }
}

/**
 * Returns XDRS document for this SimpleID installation.
 * 
 */
function simpleid_xrds() {
    global $xtpl;
    
    header('Content-Type: application/xrds+xml');
    header('Content-Disposition: inline; filename=yadis.xml');
    
    $xtpl->assign('simpleid_base_url', htmlspecialchars(simpleid_url(), ENT_QUOTES, 'UTF-8'));
    $xtpl->parse('xrds.op_xrds');
    $xtpl->parse('xrds');
    $xtpl->out('xrds');
}


?>
