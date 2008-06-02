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


include "config.inc";
include "common.inc";
include "lib/xtemplate.class.php";
include "openid.inc";
include "user.inc";
include "cache.inc";

define('SIMPLEID_VERSION', '0.5.1');
define('CACHE_DIR', SIMPLEID_CACHE_DIR);

simpleid_start();

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
    
    extension_init();
    user_init();
    
    // Clean stale assocations
    cache_gc(SIMPLEID_ASSOC_EXPIRES_IN, 'association');
    
    openid_fix_post($_REQUEST);
    
    $q = (isset($_REQUEST['q'])) ? $_REQUEST['q'] : '';
    $q = explode('/', $q);
    
    switch ($q[0]) {
        case 'continue':
            simpleid_continue();
            break;
        case 'send':
            simpleid_send();
            break;
        case 'autorelease':
            simpleid_autorelease();
            break;
        case 'openid':
            simpleid_process_openid();
            break;
        case 'login':
            user_login();
            break;
        case 'logout':
            user_logout();
            break;
        case 'user':
            if (isset($q[1])) {
                user_public_page($q[1]);
            } else {
                user_public_page();
            }
            break;
        case 'xrds':
            user_xrds($q[1]);
            break;
        default:
            if (isset($_REQUEST['openid.mode'])) {
                simpleid_process_openid($_REQUEST);                
                return;
            } else {
                user_page();
            }
    }
}

function simpleid_autorelease() {
    global $user;
    

    $rps = simpleid_rp_load_all($user['uid']);
    
    if (isset($_POST['autorelease'])) {
        foreach ($_POST['autorelease'] as $realm => $autorelease) {
            if (isset($rps[$realm])) {
                $rps[$realm]['auto_release'] = ($autorelease) ? 1 : 0;
            }
        }
    }
    
    if (isset($_POST['update-all'])) {
        foreach ($rps as $realm => $rp) {
            $rps[$realm]['auto_release'] = (isset($_POST['autorelease'][$realm]) && $_POST['autorelease'][$realm]) ? 1 : 0;
        }
    }
    
    simpleid_rp_save_all($user['uid'], $rps);
    
    set_message('Your preferences have been saved.');
    user_page();
    
}

/**
 * Entry point for OpenID messages
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
 */
function simpleid_associate($request) {
    global $version;
    
    $supported_assoc_types = array('HMAC-SHA1');
    if (OPENID_SHA256_SUPPORTED) $supported_assoc_types[] = 'HMAC-SHA256';
    
    $supported_session_types = array('no-encryption', 'DH-SHA1');
    if (OPENID_SHA256_SUPPORTED) $supported_session_types[] = 'DH-SHA256';

    // Common Request Parameters [8.1.1]
    $assoc_type = $request['openid.assoc_type'];
    $session_type = $request['openid.session_type'];
    
    // Diffie-Hellman Request Parameters [8.1.2]
    $dh_modulus = $request['openid.dh_modulus'];
    $dh_gen = $request['openid.dh_gen'];
    $dh_consumer_public = $request['openid.dh_consumer_public'];
    
    if ((!$session_type) || (!$assoc_type)) {
        openid_direct_error('openid.session_type or openid.assoc_type not set');
        return;
    }
    
    // Check if the assoc_type is supported
    if (!in_array($assoc_type, $supported_assoc_types)) {
        $error = array(
            'error_code' => 'unsupported-type',
            'session_type' => 'DH-SHA1',
            'assoc_type' => 'HMAC-SHA1'
        );
        openid_direct_error('The association type is not supported by SimpleID.', $error, $version);
        return;
    }
    // Check if the assoc_type is supported
    if (!in_array($session_type, $supported_session_types)) {
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

define('CREATE_ASSOCIATION_STATELESS', 2);
define('CREATE_ASSOCIATION_DEFAULT', 1);

function _simpleid_create_association($mode = CREATE_ASSOCIATION_DEFAULT, $assoc_type = 'HMAC-SHA1', $session_type = 'no-encryption', $dh_modulus = NULL, $dh_gen = NULL, $dh_consumer_public = NULL) {
    $secret_size = array('HMAC-SHA1' => 20, 'HMAC-SHA256' => 32);
    $hmac_funcs = array('HMAC-SHA1' => '_openid_hmac_sha1', 'HMAC-SHA256' => '_openid_hmac_sha256');
    $hash_funcs = array('DH-SHA1' => '_openid_sha1', 'DH-SHA256' => '_openid_sha256');
    
    $assoc_handle = dechex(intval(time())) . bin2hex(_openid_get_bytes(4));
    $expires_in = SIMPLEID_ASSOC_EXPIRES_IN;
    
    $secret = _openid_get_bytes($secret_size[$assoc_type]);
    
    $response = array(
        'session_type' => $session_type,
        'assoc_handle' => $assoc_handle,
        'assoc_type' => $assoc_type,
        'expires_in' => $expires_in
    );
    
    if ($session_type == 'no-encryption') {
        $mac_key = base64_encode(call_user_func($hmac_funcs[$assoc_type], $secret, $response['assoc_handle']));
        $response['mac_key'] = $mac_key;
    } elseif ($session_type == 'DH-SHA1' || $session_type == 'DH-SHA256') {
        $dh_assoc = openid_dh_server_assoc($secret, $dh_consumer_public, $dh_modulus, $dh_gen, $hash_funcs[$session_type]);
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


define('CHECKID_APPROVAL_REQUIRED', 2);
define('CHECKID_OK', 1);
define('CHECKID_LOGIN_REQUIRED', -1);
define('CHECKID_IDENTITIES_NOT_MATCHING', -2);
define('CHECKID_IDENTITY_NOT_EXIST', -3);

function simpleid_checkid($request) {
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
    
    /*
     * Here, we should verify whether $request['openid.return_to'] is in fact
     * an OpenID endpoint.  [9.2.1]
     */

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
    if ($request['openid.identity'] == 'http://specs.openid.net/auth/2.0/identifier_select') {        
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
    
    // Check 3: For checkid_immediate, the user must already have given
    // permission to log in automatically.    
    $rp = simpleid_rp_load($uid, $realm);
    simpleid_rp_save($uid, $realm);
    
    if ($rp['auto_release'] == 1) {
        return CHECKID_OK;
    } else {
        return CHECKID_APPROVAL_REQUIRED;
    }
}

function simpleid_checkid_ok($request) {
    global $version;
    
    $message = array(
        'openid.mode' => 'id_res',
        'openid.op_endpoint' => SIMPLEID_BASE_URL,
        'openid.identity' => $request['openid.identity'],
        'openid.return_to' => $request['openid.return_to'],
        'openid.response_nonce' => openid_nonce(),
    );
    
    if (isset($request['openid.assoc_handle'])) $message['openid.assoc_handle'] = $request['openid.assoc_handle'];
    
    if ($version == OPENID_VERSION_2) {
        $message['openid.claimed_id'] = $request['openid.claimed_id'];
    }
    
    if ($version == OPENID_VERSION_1_1) {
        // Check for a 1.1 nonce
        $parts = parse_url($request['openid.return_to']);
        if (preg_match('/nonce=([^&]+)/', $parts['query'], $matches)) {
            $message['nonce'] = $matches[1];
        }
    }
    
    $message = array_merge($message, extension_invoke_all('id_res', $request));
    
    return openid_indirect_message($message, $version);
}

function simpleid_checkid_approval_required($request) {
    global $version;
    
    if ($version == OPENID_VERSION_2) {
        $message = array('openid.mode' => 'setup_needed');
    } else {
        $request['openid.mode'] = 'checkid_setup';
        $message = array(
            'openid.mode' => 'id_res',            
            'openid.user_setup_url' => SIMPLEID_BASE_URL . '/index.php?q=continue&s=' . rawurlencode(pickle($request))
        );
    }
    
    return openid_indirect_message($message, $version);
}

function simpleid_checkid_login_required($request, $auth_release_realm = NULL) {
    global $version;
    
    if ($version == OPENID_VERSION_2) {
        $message = array('openid.mode' => 'setup_needed');
    } else {    
        $message = array(
            'openid.mode' => 'id_res',
            'openid.user_setup_url' => SIMPLEID_BASE_URL . '/index.php?q=login&destination=continue&s=' . rawurlencode(pickle($request))
        );
    }
    
    return openid_indirect_message($message, $version);
}

/**
 * Provides a message indicating a negative assertion  [10.2]
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
    
    $response['openid.signed'] = implode(',', $signed_fields);
  
    // Generate signature for this message
    $response['openid.sig'] = _openid_signature($assoc, $response, $to_sign);
    return $response;
}

/**
 * Verify signatures generated using stateless mode [11.4.2]
 */
function simpleid_authenticate($request) {
    global $version;
    
    $is_valid = TRUE;
  
    $assoc = cache_get('association', $request['openid.assoc_handle']);
  
    if (!$assoc || !$assoc['assoc_type']) {
        $is_valid = FALSE;
    } else {
        $signed_keys = explode(',', $request['openid.signed']);
        $signature = _openid_signature($assoc, $request, $signed_keys);
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
 */
function simpleid_continue() {
    simpleid_process_openid(unpickle($_REQUEST['s']));
}

/**
 * Indirect communication .. give the user
 * a chance to make changes to any data
 * being requested by an RP.
 */
function simpleid_rp_form($request, $response) {
    global $user;
    global $xtpl;
    global $version;
    
    user_block(false);

    $realm = openid_get_realm($request, $version);
    
    $xtpl->assign('state', pickle($response));
    $xtpl->assign('realm', htmlspecialchars($realm));

    if ($response['openid.mode'] == 'cancel') {
        $xtpl->assign('request_state', pickle($request));
        $xtpl->assign('return_to', htmlspecialchars($request['openid.return_to']));
        $xtpl->assign('identity', htmlspecialchars($request['openid.identity']));
        $xtpl->parse('main.rp.cancel');
    } else {        
        $rp = simpleid_rp_load($user['uid'], $realm);
        
        $extensions = extension_invoke_all('form', $request, $rp);
        $xtpl->assign('extensions', implode($extensions));
        
        $xtpl->parse('main.rp.setup');
    }
    
    $xtpl->parse('main.rp');
    
    $xtpl->assign('title', 'OpenID Login');
    $xtpl->parse('main');
    
    $xtpl->out('main');
}


/**
 * 2nd part of 2-step user interaction
 * take the values they have updated
 * in the previous form and return them
 * to the original RP that had requested them.
 */
function simpleid_send() {
    global $user, $version;
    $uid = $user['uid'];
    
    $response = unpickle($_REQUEST['s']);
    $version = openid_get_version($response);
    $return_to = $response['openid.return_to'];
    if (!$return_to) $return_to = $_REQUEST['openid.return_to'];
    
    if ($_REQUEST['op'] == 'Cancel') {
        $response = simpleid_checkid_error(false);
        set_message('Log in cancelled.');
    } else {
        simpleid_rp_save($uid, $_REQUEST['openid.realm'], array('auto_release' => $_REQUEST['autorelease']));
        $response = simpleid_sign($response, $response['openid.assoc_handle']);
        set_message('You were logged in successfully.');
    }

    if ($return_to) {
        redirect_form($return_to, $response);
    } else {
        user_page();
    }
}


/**
 * Wrapper for saving and loading Relying Parties
 * with which users have interacted.
 */
function simpleid_rp_save($uid, $realm, $details = array()) {
    $now = time();
    
    $rps = simpleid_rp_load_all($uid);
    
    if ($rps == NULL) $rps = array();

    if (!isset($rps[$realm])) {
        if ($details['auto_release'] != 0) {
            $details['auto_release'] = 1;
        }
        
        $rps[$realm] = array_merge($details, array('uid' => $uid, 'realm' => $realm, 'first_time' => $now, 'last_time' => $now));
    } else {
        $rps[$realm] = array_merge($details, $rps[$realm]);
        $rps[$realm]['last_time'] = $now;
    }
    cache_set('rp', $uid, $rps);
}

function simpleid_rp_load($uid, $realm) {
    $rps = cache_get('rp', $uid);
    if (isset($rps[$realm])) {
        return $rps[$realm];
    } else {
        return NULL;
    }
}

function simpleid_rp_load_all($uid) {
    return cache_get('rp', $uid);
}

function simpleid_rp_save_all($uid, $rps) {
    cache_set('rp', $uid, $rps);
}

?>
