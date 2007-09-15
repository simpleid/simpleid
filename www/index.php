<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007
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

define('SIMPLEID_VERSION', '0.2');

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
    
    _openid_fix_post($_REQUEST);
    
    $q = (isset($_REQUEST['q'])) ? $_REQUEST['q'] : '';
    
    switch ($q) {
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
        default:
            if (isset($_REQUEST['openid.mode'])) {
                simpleid_process_openid();
                return;
            } else {
                user_page();
            }
    }
}

function simpleid_autorelease() {
    global $xtpl;
    global $user;
    
    if (!isset($_POST['op'])) {
        $xtpl->assign('realm', $_REQUEST['openid.realm']);
        $xtpl->parse('main.autorelease');
    
        $xtpl->assign('title', 'OpenID Setup');
        $xtpl->parse('main');
    
        $xtpl->out('main');
    } else {
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
}

function simpleid_process_openid() {
    switch ($_REQUEST['openid.mode']) {
        case 'associate':
            simpleid_associate($_REQUEST);
            return;
        case 'checkid_immediate':
        case 'checkid_setup':
            return simpleid_checkid($_REQUEST);
        case 'check_authentication':
            simpleid_authenticate($_REQUEST);
            break;
    }
}

/**
 * Processes an association request from a relying party.  [8]
 *
 */
function simpleid_associate($request) {
    $session_type = $request['openid.session_type'];
    $assoc_type = $request['openid.assoc_type'];
    $dh_modulus = $request['openid.dh_modulus'];
    $dh_gen = $request['openid.dh_gen'];
    $dh_consumer_public = $request['openid.dh_consumer_public'];

    $assoc_handle = _openid_nonce();
    $expires_in = SIMPLEID_ASSOC_EXPIRES_IN;

    // Clean stale assocations
    cache_gc(SIMPLEID_ASSOC_EXPIRES_IN, 'association');
    
    $response = array(
        'ns' => 'http://specs.openid.net/auth/2.0',
        'session_type' => $session_type,
        'assoc_handle' => $assoc_handle,
        'assoc_type' => $assoc_type,
        'expires_in' => $expires_in
    );

    $secret = _openid_get_bytes(20);
    
    if ($session_type == '' || $session_type == 'no-encryption') {
        if ($assoc_type == 'HMAC-SHA1') {
            $mac_key = _openid_hmac($secret, $response['assoc_handle']);
            $response['mac_key'] = $mac_key;
        } elseif ($assoc_type == 'HMAC-SHA256') {
      // Not yet supported
        }
    } elseif ($session_type == 'DH-SHA1' || $session_type == 'DH-SHA256') {
        $dh_assoc = openid_dh_server_assoc($request, $secret);
        $mac_key = base64_encode($secret);
        $response['dh_server_public'] = $dh_assoc['dh_server_public'];
        $response['enc_mac_key'] = $dh_assoc['enc_mac_key'];
    }

    // Save the association for reference when dealing
    // with future requests from the same RP.
    cache_set('association', $assoc_handle, array('assoc_handle' => $assoc_handle, 'assoc_type' => $assoc_type, 'session_type' => $session_type, 'mac_key' => $mac_key, 'created' => time()));  

    // PHP can only handle SHA1 at the moment
    // need to find or write a library for it
    if ($assoc_type == 'HMAC-SHA256' || $session_type == 'DH-SHA256') {
        $message = _openid_create_message(simpleid_association_error());
    } else {
        $message = _openid_create_message($response);
    }

    header('HTTP/1.1 200 OK');
    header("Content-Type: text/plain");
    print $message;
}

/**
 * Creates a PHP array containing a OpenID message indicating an unsuccessful
 * association response.  [8.2.4].
 */
function simpleid_association_error() {
  return array(
    'ns' => 'http://specs.openid.net/auth/2.0',
    'error' => 'The session type or association type is not supported by this provider.',
    'error_code' => 'unsupported-type',
    'session_type' => 'DH-SHA1',
    'assoc_type' => 'HMAC-SHA1'
  );
}

/**
 * Associate using Diffie-Hellman key exchange
 */
function openid_dh_server_assoc($request, $secret) {
  if (empty($request['openid.dh_consumer_public'])) {
    return FALSE;
  }
  
  if (isset($request['openid.dh_modulus'])) {
    $mod = _openid_dh_base64_to_long($request['openid.dh_modulus']);
  }
  else {
    $mod = OPENID_DH_DEFAULT_MOD;
  }

  if (isset($request['openid.dh_gen'])) {
    $gen = _openid_dh_base64_to_long($request['openid.dh_gen']);
  }
  else {
    $gen = OPENID_DH_DEFAULT_GEN;
  }

  $r = _openid_dh_rand($mod);
  $private = bcadd($r, 1);
  $public = bcpowmod($gen, $private, $mod);
  
  $cpub = _openid_dh_base64_to_long($request['openid.dh_consumer_public']);
  $shared = bcpowmod($cpub, $private, $mod);
  $mac_key = _openid_dh_xorsecret($shared, $secret);
  $enc_mac_key = base64_encode($mac_key);
  $spub64 = _openid_dh_long_to_base64($public);
  return array(
    'dh_server_public' => $spub64,
    'enc_mac_key' => $enc_mac_key
    );
}

define('CHECKID_APPROVAL_REQUIRED', 2);
define('CHECKID_OK', 1);
define('CHECKID_LOGIN_REQUIRED', -1);
define('CHECKID_IDENTITIES_NOT_MATCHING', -2);
define('CHECKID_IDENTITY_NOT_EXIST', -3);


function simpleid_checkid($request) {
    $result = _simpleid_checkid($request);
    
    switch ($result) {
        case CHECKID_APPROVAL_REQUIRED:
            if ($request['openid.mode'] == 'check_immediate') {
                $response = simpleid_checkid_approval_required($request);
                $response = simpleid_sign($response);
                $message = _openid_create_message($response);
                return redirect_form($request['openid.return_to'], $message);
            } else {
                $response = simpleid_checkid_ok($request);
                return simpleid_rp_form($request, $response);
            }
            break;
        case CHECKID_OK:
            $response = simpleid_checkid_ok();
            $response = simpleid_sign($response);
            $message = _openid_create_message($response);
            return redirect_form($request['openid.return_to'], $message);
            break;
        case CHECKID_LOGIN_REQUIRED:
            if ($request['openid.mode'] == 'check_immediate') {
                $response = simpleid_checkid_login_required($request);
                $response = simpleid_sign($response);
                $message = _openid_create_message($response);
                return redirect_form($request['openid.return_to'], $message);
            } else {
                $_SESSION['openidrequest'] = $request;
                user_login_form('continue');
                exit;
            }
            break;
        case CHECKID_IDENTITIES_NOT_MATCHING:
        case CHECKID_IDENTITY_NOT_EXIST:
            $response = simpleid_checkid_error($request);
            if ($request['openid.mode'] == 'check_immediate') {                
                $response = simpleid_sign($response);
                $message = _openid_create_message($response);
                return redirect_form($request['openid.return_to'], $message);
            } else {                
                return simpleid_rp_form($request, $response);                
            }
            break;        
    }
}

function _simpleid_checkid(&$request) {
    global $user;
    
    // OpenID 1.1 backwards compatibility
    if (empty($request['openid.realm'])) {
        $request['openid.realm'] = $request['openid.trust_root'];
    }
    
    // Check 1: Is the user logged into SimpleID as any user?
    if ($user == NULL) {        
        return CHECKID_LOGIN_REQUIRED;
    }
    
    // Check 2: Is the user logged in as the same identity as the identity requested?
    // Choose the identity URL for the user automatically
    if ($request['openid.identity'] == 'http://openid.net/identifier_select/2.0') {
        $test_user = user_load($uid);
        $identity = $test_user['identity'];
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
    $uid = $user['uid'];
    $rp = simpleid_rp_load($uid, $request['openid.realm']);
    simpleid_rp_save($uid, $request['openid.realm']);
    
    if ($rp['auto_release'] == 1) {
        return CHECKID_OK;
    } else {
        return CHECKID_APPROVAL_REQUIRED;
    }
}

function simpleid_checkid_ok($request) {
    $message = array(
        'openid.ns' => 'http://specs.openid.net/auth/2.0',
        'openid.mode' => 'id_res',
        'openid.op_endpoint' => SIMPLEID_BASE_URL,
        'openid.identity' => $request['openid.identity'],
        'openid.claimed_id' => $request['openid.identity'],
        'openid.return_to' => $request['openid.return_to'],
        'openid.response_nonce' => _openid_nonce(),
        'openid.assoc_handle' => $request['openid.assoc_handle']
    );
    
    // Check for a 1.1 nonce
    $parts = parse_url($request['openid.return_to']);
    if (preg_match('/nonce=([^&]+)/', $parts['query'], $matches)) {
        $message['nonce'] = $matches[1];
    }
    
    $message = array_merge($message, extension_invoke_all('checkid_ok', $request));
    
    return $message;
}

function simpleid_checkid_approval_required($request) {
    $message = array(
        'openid.ns' => 'http://specs.openid.net/auth/2.0',
        'openid.mode' => 'id_res',
        'openid.user_setup_url' => SIMPLEID_BASE_URL . '/index.php?q=autorelease&openid.realm=' . $reqiest['openid.realm']
    );
    
    if (isset($request['openid.ns']) && ($request['openid.ns'] == 'http://specs.openid.net/auth/2.0'))
        $message['openid.mode'] = 'setup_needed';
    return $message;
}

function simpleid_checkid_login_required($request, $auth_release_realm = NULL) {
    $message = array(
        'openid.ns' => 'http://specs.openid.net/auth/2.0',
        'openid.mode' => 'id_res',
        'openid.user_setup_url' => SIMPLEID_BASE_URL . '/index.php?q=login'
    );
    if (isset($request['openid.ns']) && ($request['openid.ns'] == 'http://specs.openid.net/auth/2.0'))
        $message['openid.mode'] = 'setup_needed';
    return $message;
}

// 11.2. Negative Assertions
function simpleid_checkid_error($request) {
    $message = array(
        'openid.ns' => 'http://specs.openid.net/auth/2.0',
    );
    if ($request['openid.mode'] == 'checkid_immediate') {
        $message['openid.mode'] = 'setup_needed';
    } else { 
        $message['openid.mode'] = 'cancel';
    }
    return $message;
}

// 9.2.2.2. Verifying Directly with the Identity Provider
// 9.2.2.2.2. Response Parameters
// Request is: Exact copies of all fields from the authentication response
function simpleid_authenticate($request) {
  $is_valid = TRUE;
  
  // Use the request openid.assoc_handle to look up
  // how this message should be signed, based on
  // a previously-created association.
  $assoc_type = 'HMAC-SHA1';
  $assoc = cache_get('association', $request['openid.assoc_handle']);
  
  if ($assoc && $assoc['assoc_type'] != '') {
    $assoc_type = $assoc['assoc_type'];
  }

  $signed_keys = explode(',', $request['openid.signed']);
  $signature = _openid_signature($assoc, $request, $signed_keys);

  if ($signature != $request['openid.sig']) {
    $is_valid = FALSE;
  }

  if ($is_valid) {
    $response = array(
        'ns' => 'http://specs.openid.net/auth/2.0',
        'is_valid' => 'true'
    );
  }
  else {
    $response = array(
      'ns' => 'http://specs.openid.net/auth/2.0',
      'is_valid' => 'false',
      'invalidate_handle' => $request['openid.assoc_handle'] // optional, An association handle sent in the request
    );
  }

  $message = _openid_create_message($response);
  header("Content-Type: text/plain");
  print $message;  
}


/**
 * Support continuing an OpenID authentication request
 * say, if the user must log in first.
 */
function simpleid_continue() {
    if (isset($_SESSION['openidrequest'])) {
        $message = _openid_create_message($_SESSION['openidrequest']);
        unset($_SESSION['openidrequest']);
        redirect_form('index.php', $message);
    }
}

/**
 * Indirect communication .. give the user
 * a chance to make changes to any data
 * being requested by an RP.
 */
function simpleid_rp_form($request, &$response) {
    global $user;
    global $xtpl;
    
    user_block(false);

    $realm = $request['openid.realm'];
    
    $form = array_merge($request, $response);

    foreach ($form as $key => $value) {
        if (strpos($key, 'openid.') === 0 || $key == 'nonce') {
            $xtpl->assign('name', htmlspecialchars($key));
            $xtpl->assign('value', htmlspecialchars($value));
            $xtpl->parse('main.rp.parameter');
        }
    }
  
    $xtpl->assign('realm', htmlspecialchars($realm));

    if ($form['openid.mode'] == 'cancel') {
        $xtpl->assign('identity', htmlspecialchars($form['openid.identity']));
        $xtpl->parse('main.rp.cancel');
    } else {        
        // Check the user's auto-submit preference for this RP
        // (default to on)
        $auto_submit_checked = TRUE;
        $rp = simpleid_rp_load($user['uid'], $realm);
        
        $extensions = extension_invoke_all('form', $form, $rp);
        $xtpl->assign('extensions', implode($extensions));

    
        if ($rp && $rp['auto_release'] == 0) {
            $auto_submit_checked = FALSE;
        }
    
        if ($auto_submit_checked) $xtpl->assign('auto_release', 'checked="checked"');
        
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
function simpleid_send($response = NULL) {
    global $user;
    $uid = $user['uid'];

    if (!$response) $response = $_REQUEST;
    
    if ($response['op'] == 'Cancel') {
        $response['openid.mode'] = 'cancel';
    } else {
        simpleid_rp_save($uid, $_REQUEST['openid.realm'], array('auto_release' => $_REQUEST['autorelease']));
    }
    
    unset($response['autosubmit']);
    unset($response['q']);
    unset($response['op']);
    unset($response[session_name()]);

    $response = simpleid_sign($response);
    $message = _openid_create_message($response);
    redirect_form($response['openid.return_to'], $message);
}

function simpleid_sign($response) {
  $signed_keys = array('return_to', 'response_nonce', 'assoc_handle', 'identity');
  $signed_keys = array_merge($signed_keys, extension_invoke_all('signed_keys', $response));
  $response['openid.signed'] = implode(',', $signed_keys);
  
  // Use the request openid.assoc_handle to look up
  // how this message should be signed, based on
  // a previously-created association.
  $assoc = cache_get('association', $response['openid.assoc_handle']);
  
  // Generate signature for this message
  $response['openid.sig'] = _openid_signature($assoc, $response, $signed_keys);
  return $response;
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
