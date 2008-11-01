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
 
 
include "config.inc";
include "config.default.inc";
include "common.inc";
include "lib/xtemplate.class.php";
include "openid.inc";
include "user.inc";
include "cache.inc";

define('SIMPLEID_VERSION', '0.7');
define('CACHE_DIR', SIMPLEID_CACHE_DIR);


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

    $rps = simpleid_rp_load_all($user['uid']);
    
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
    
    simpleid_rp_save_all($user['uid'], $rps);
    
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

/**
 * Checks whether the current user logged into SimpleID matches the identity
 * supplied in an OpenID request.
 *
 * @param mixed &$request the OpenID request
 * @return int one of CHECKID_OK, CHECKID_APPROVAL_REQUIRED, CHECKID_IDENTITY_NOT_EXIST,
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
    $response['openid.sig'] = _openid_signature($assoc, $response, $to_sign);
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
 */
function simpleid_rp_form($request, $response) {
    global $user;
    global $xtpl;
    global $version;
    
    user_block(false);

    $realm = openid_get_realm($request, $version);
    
    $xtpl->assign('token', get_form_token('rp'));
    $xtpl->assign('state', pickle($response));
    $xtpl->assign('realm', htmlspecialchars($realm, ENT_QUOTES, 'UTF-8'));

    if ($response['openid.mode'] == 'cancel') {
        $xtpl->assign('request_state', pickle($request));
        $xtpl->assign('return_to', htmlspecialchars($request['openid.return_to'], ENT_QUOTES, 'UTF-8'));
        $xtpl->assign('identity', htmlspecialchars($request['openid.identity'], ENT_QUOTES, 'UTF-8'));
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
 * Saves the user's preferences and other data in relation to a relying party.
 *
 * @param string $uid the user name
 * @param string $realm the openid.realm of the relying party
 * @param array $details an associative array of the data to save
 * @see cache_set()
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

/**
 * Loads the user's preferences and other data in relation to a relying party.
 *
 * @param string $uid the user name
 * @param string $realm the openid.realm of the relying party
 * @return array an associative array of the data
 * @see cache_get()
 */
function simpleid_rp_load($uid, $realm) {
    $rps = cache_get('rp', $uid);
    if (isset($rps[$realm])) {
        return $rps[$realm];
    } else {
        return NULL;
    }
}

/**
 * Loads the user's preferences and other data in relation to all relying parties.
 *
 * @param string $uid the user name
 * @return array an associative array of the data, with the openid.realm URIs as
 * key
 */
function simpleid_rp_load_all($uid) {
    return cache_get('rp', $uid);
}

/**
 * Saves the user's preferences and other data in relation to all relying parties.
 *
 * @param string $uid the user name
 * @param array $rps an associative array of the data as obtained from the
 * {@link simpleid_rp_load_all()} function
 */
function simpleid_rp_save_all($uid, $rps) {
    cache_set('rp', $uid, $rps);
}

?>
