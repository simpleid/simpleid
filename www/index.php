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
 
include_once "version.inc.php";
include_once "config.php";
include_once "config.default.php";
include_once "log.inc.php";
include_once "locale.inc.php";
include_once "common.inc.php";
include_once "simpleweb.inc.php";
include_once "openid.inc.php";
include_once "discovery.inc.php";
include_once "user.inc.php";
include_once "cache.inc.php";
include_once SIMPLEID_STORE . ".store.php";
include_once "page.inc.php";
include "lib/xtemplate.class.php";

define('CACHE_DIR', SIMPLEID_CACHE_DIR);

/**
 */
define('CHECKID_OK', 127);
define('CHECKID_RETURN_TO_SUSPECT', 3);
define('CHECKID_APPROVAL_REQUIRED', 2);
define('CHECKID_LOGIN_REQUIRED', -1);
define('CHECKID_IDENTITIES_NOT_MATCHING', -2);
define('CHECKID_IDENTITY_NOT_EXIST', -3);
define('CHECKID_PROTOCOL_ERROR', -127);

define('ASSOCIATION_PRIVATE', 2);
define('ASSOCIATION_SHARED', 1);


/**
 * This variable holds the version of the OpenID specification associated with
 * the current OpenID request.  This can be either {@link OPENID_VERSION_1_1}
 * or {@link OPENID_VERSION_2}.
 *
 * @global float $version
 */
$version = OPENID_VERSION_1_1;

/**
 * This variable holds an instance of the XTemplate engine.
 *
 * @global object $xtpl
 */
$xtpl = NULL;

/**
 * This variable holds the combined $_GET and $_POST superglobal arrays.
 * This is then passed through {@link openid_fix_request()}.
 *
 * @global array $GETPOST
 */
$GETPOST = array();

simpleid_start();

/**
 * Entry point for SimpleID.
 *
 * @see user_init()
 */
function simpleid_start() {
    global $xtpl, $GETPOST;
    
    locale_init(SIMPLEID_LOCALE);

    $xtpl = new XTemplate('html/template.xtpl');
    $xtpl->assign('version', SIMPLEID_VERSION);
    $xtpl->assign('base_path', get_base_path());
    $xtpl->assign('footer_doc', t('Documentation'));
    $xtpl->assign('footer_support', t('Support'));
    
    // Check if the configuration file has been defined
    if (!defined('SIMPLEID_BASE_URL')) {
        log_fatal('No configuration file found.');
        indirect_fatal_error(t('No configuration file found.  See the <a href="!url">manual</a> for instructions on how to set up a configuration file.', array('!url' => 'http://simpleid.koinic.net/documentation/getting-started')));
    }
    
    if (!is_dir(SIMPLEID_IDENTITIES_DIR)) {
        log_fatal('Identities directory not found.');
        indirect_fatal_error(t('Identities directory not found.  See the <a href="!url">manual</a> for instructions on how to set up SimpleID.', array('!url' => 'http://simpleid.koinic.net/documentation/getting-started')));
    }
    
    if (!is_dir(SIMPLEID_CACHE_DIR) || !is_writeable(SIMPLEID_CACHE_DIR)) {
        log_fatal('Cache directory not found or not writeable.');
        indirect_fatal_error(t('Cache directory not found or not writeable.  See the <a href="!url">manual</a> for instructions on how to set up SimpleID.', array('!url' => 'http://simpleid.koinic.net/documentation/getting-started')));
    }
    
    
    if (!is_dir(SIMPLEID_STORE_DIR) || !is_writeable(SIMPLEID_STORE_DIR)) {
        log_fatal('Store directory not found or not writeable.');
        indirect_fatal_error(t('Store directory not found or not writeable.  See the <a href="!url">manual</a> for instructions on how to set up SimpleID.', array('!url' => 'http://simpleid.koinic.net/documentation/getting-started')));
    }
    
    if ((@ini_get('register_globals') === 1) || (@ini_get('register_globals') === '1') || (strtolower(@ini_get('register_globals')) == 'on')) {
        log_fatal('register_globals is enabled in PHP configuration.');
        indirect_fatal_error(t('register_globals is enabled in PHP configuration, which is not supported by SimpleID.  See the <a href="!url">manual</a> for further information.', array('!url' => 'http://simpleid.koinic.net/documentation/getting-started/system-requirements')));
    }
    
    if (!bignum_loaded()) {
        log_fatal('gmp/bcmath PHP extension not loaded.');
        indirect_fatal_error(t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'gmp/bcmath', '!url' => 'http://simpleid.koinic.net/documentation/getting-started/system-requirements')));
    }
    if (!function_exists('preg_match')) {
        log_fatal('pcre PHP extension not loaded.');
        indirect_fatal_error(t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'pcre', '!url' => 'http://simpleid.koinic.net/documentation/getting-started/system-requirements')));
    }
    if (!function_exists('session_start')) {
        log_fatal('session PHP extension not loaded.');
        indirect_fatal_error(t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'session', '!url' => 'http://simpleid.koinic.net/documentation/getting-started/system-requirements')));
    }
    if (!function_exists('xml_parser_create_ns')) {
        log_fatal('xml PHP extension not loaded.');
        indirect_fatal_error(t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'xml', '!url' => 'http://simpleid.koinic.net/documentation/getting-started/system-requirements')));
    }
    if (!function_exists('hash')) {
        log_fatal('hash PHP extension not loaded.');
        indirect_fatal_error(t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'hash', '!url' => 'http://simpleid.koinic.net/documentation/getting-started/system-requirements')));
    }

    openid_fix_request();
    $GETPOST = array_merge($_GET, $_POST);
    
    $q = (isset($GETPOST['q'])) ? $GETPOST['q'] : '';
    
    extension_init();
    user_init($q);
    log_info('Session opened for "' . $q . '" [' . $_SERVER['REMOTE_ADDR'] . ', ' . gethostbyaddr($_SERVER['REMOTE_ADDR']) . ']');
    
    // Clean stale assocations
    cache_expire(array(
        'association' => SIMPLEID_ASSOC_EXPIRES_IN,
        'stateless' => 300)
    );
    
    simpleid_route($q);
}

/**
 * Dispatches to the correct SimpleID function based on the request path.  The
 * request path usually comes from the q parameter in the query string (which may
 * be inserted by mod_rewrite), but can come from other functions as well.
 *
 * @param string $q the request path
 */
function simpleid_route($q) {
    $routes = array(
        'continue' => 'simpleid_continue',
        'login' => 'user_login',
        'logout' => 'user_logout',
        'my/dashboard' => 'page_dashboard',
        'my/sites' => 'page_sites',
        'my/profile' => 'page_profile',
        'openid/consent' => 'simpleid_openid_consent',
        'ppid/(.*)' => 'user_ppid_page',
        'user' => 'user_public_page',
        'user/(.+)' => 'user_public_page',
        'xrds/(.*)' => 'user_xrds',
        'xrds' => 'simpleid_xrds',
    );
    $routes = array_merge($routes, extension_invoke_all('routes'), array('.*' => 'simpleid_index'));
    
    simpleweb_run($routes, $q);
}

/**
 * The default route, called when the q parameter is missing or is invalid.
 *
 * This function performs the following:
 *
 * - If openid.mode is present, then the request is an OpenID request.  This
 *   is passed to {@link simpleid_process_openid()}
 * - If the Accept HTTP header contains the expression application/xrds+xml, then
 *   the request is a YADIS discovery request for SimpleID as an OpenID provider.  Thi
 *   is passed to {@link simpleid_xrds()}
 * - Otherwise, the dashboard or the login page is displayed to the user as
 *   appropriate
 *
 */
function simpleid_index() {
    global $GETPOST;
    
    log_debug('simpleid_index');
    
    $content_type = negotiate_content_type(array('text/html', 'application/xml', 'application/xhtml+xml', 'application/xrds+xml'));
    
    header('Vary: Accept');
    if (isset($GETPOST['openid.mode'])) {
        simpleid_process_openid($GETPOST);
        return;
    } elseif ($content_type == 'application/xrds+xml') {
        simpleid_xrds();
    } else {
        // Point to SimpleID's XRDS document
        header('X-XRDS-Location: ' . simpleid_url('xrds'));
        page_dashboard();
    }
}


/**
 * Process an OpenID request.
 *
 * This function determines the version of the OpenID specification that is
 * relevant to this request, checks openid.mode and passes the
 * request on to the function required to process the request.
 *
 * The OpenID request expressed as an array contain key-value pairs corresponding
 * to the HTTP request.  This is usually contained in the <code>$_REQUEST</code>
 * variable.
 *
 * @param array $request the OpenID request
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
            check_https('redirect', true, simpleid_url('continue', 's=' . rawurlencode(pickle($request)), false, 'https'));
            
            return simpleid_checkid($request);
        case 'check_authentication':
            simpleid_check_authentication($request);
            break;
        default:
            if (isset($request['openid.return_to'])) {
                // Indirect communication - send error via indirect communication.
                header_response_code('400 Bad Request');
                set_message(t('Invalid OpenID message.'));
                page_dashboard();
            } else {
                // Direct communication
                openid_direct_error('Invalid OpenID message.');
            }
    }
}

/**
 * Processes an association request from a relying party.
 *
 * An association request has an openid.mode value of
 * associate.  This function checks whether the association request
 * is valid, and if so, creates an association and sends the response to
 * the relying party.
 *
 * @see _simpleid_create_association()
 * @param array $request the OpenID request
 * @link http://openid.net/specs/openid-authentication-1_1.html#mode_associate, http://openid.net/specs/openid-authentication-2_0.html#associations
 *
 */
function simpleid_associate($request) {
    global $version;
    
    log_info('OpenID association request: ' . log_array($request));
    
    $assoc_types = openid_association_types();
    $session_types = openid_session_types(is_https(), $version);

    // Common Request Parameters [8.1.1]
    if (($version == OPENID_VERSION_1_1) && !isset($request['openid.session_type'])) $request['openid.session_type'] = '';
    $assoc_type = $request['openid.assoc_type'];
    $session_type = $request['openid.session_type'];
    
    // Diffie-Hellman Request Parameters [8.1.2]
    $dh_modulus = (isset($request['openid.dh_modulus'])) ? $request['openid.dh_modulus'] : NULL;
    $dh_gen = (isset($request['openid.dh_gen'])) ? $request['openid.dh_gen'] : NULL;
    $dh_consumer_public = $request['openid.dh_consumer_public'];
    
    if (!isset($request['openid.session_type']) || !isset($request['openid.assoc_type'])) {
        log_error('Association failed: openid.session_type or openid.assoc_type not set');
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
        log_error('Association failed: The association type is not supported by SimpleID.');
        openid_direct_error('The association type is not supported by SimpleID.', $error, $version);
        return;
    }
    // Check if the session_type is supported
    if (!array_key_exists($session_type, $session_types)) {
        $error = array(
            'error_code' => 'unsupported-type',
            'session_type' => 'DH-SHA1',
            'assoc_type' => 'HMAC-SHA1'
        );
        log_error('Association failed: The session type is not supported by SimpleID.');
        openid_direct_error('The session type is not supported by SimpleID.', $error, $version);
        return;
    }
    
    if ($session_type == 'DH-SHA1' || $session_type == 'DH-SHA256') {
        if (!$dh_consumer_public) {
            log_error('Association failed: openid.dh_consumer_public not set');
            openid_direct_error('openid.dh_consumer_public not set');
            return;
        }
    }

    $response = _simpleid_create_association(ASSOCIATION_SHARED, $assoc_type, $session_type, $dh_modulus, $dh_gen, $dh_consumer_public);
    
    openid_direct_response(openid_direct_message($response, $version));
}


/**
 * Creates an association.
 *
 * This function calls {@link openid_dh_server_assoc()} where required, to 
 * generate the cryptographic values required for an association response.
 *
 * @param int $mode either ASSOCIATION_SHARED or ASSOCIATION_PRIVATE
 * @param string $assoc_type a valid OpenID association type
 * @param string $session_type a valid OpenID session type
 * @param string $dh_modulus for Diffie-Hellman key exchange, the modulus encoded in Base64
 * @param string $dh_gen for Diffie-Hellman key exchange, g encoded in Base64
 * @param string $dh_consumer_public for Diffie-Hellman key exchange, the public key of the relying party encoded in Base64
 * @return mixed if $mode is ASSOCIATION_SHARED, an OpenID response
 * to the association request, if $mode is ASSOCIATION_PRIVATE, the
 * association data for storage.
 * @link http://openid.net/specs/openid-authentication-1_1.html#anchor14, http://openid.net/specs/openid-authentication-2_0.html#anchor20
 */
function _simpleid_create_association($mode = ASSOCIATION_SHARED, $assoc_type = 'HMAC-SHA1', $session_type = 'no-encryption', $dh_modulus = NULL, $dh_gen = NULL, $dh_consumer_public = NULL) {
    global $version;
    
    $assoc_types = openid_association_types();
    $session_types = openid_session_types(is_https(), $version);
    
    $mac_size = $assoc_types[$assoc_type]['mac_size'];
    $hmac_func = $assoc_types[$assoc_type]['hmac_func'];
    
    $assoc_handle = random_id();
    $expires_in = SIMPLEID_ASSOC_EXPIRES_IN;
    
    $secret = random_bytes($mac_size);
    
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
    if ($mode == ASSOCIATION_PRIVATE) $association['private'] = 1;
    cache_set('association', $assoc_handle, $association);

    if ($mode == ASSOCIATION_SHARED) {
        log_info('Created association: ' . log_array($response));
        log_debug('***** MAC key: ' . $association['mac_key']);
        return $response;
    } else {
        log_info('Created association: private; ' . log_array($association, array('assoc_handle', 'assoc_type')));
        log_debug('***** MAC key: ' . $association['mac_key']);
        return $association;
    }
}


/**
 * Processes an authentication request from a relying party.
 *
 * An authentication request has an openid.mode value of
 * checkid_setup or checkid_immediate.
 *
 * If the authentication request is a standard OpenID request about an identity
 * (i.e. contains the key openid.identity), this function calls
 * {@link simpleid_checkid_identity()} to see whether the user logged on into SimpleID
 * matches the identity supplied in the OpenID request.
 *
 * If the authentication request is not about an identity, this function calls
 * the {@link hook_checkid() checkid hook} of the loaded extensions.
 *
 * Depending on the OpenID version, this function will supply an appropriate
 * assertion.
 *
 * @param array $request the OpenID request
 *
 */
function simpleid_checkid($request) {
    global $version;
    
    $immediate = ($request['openid.mode'] == 'checkid_immediate');
    
    log_info('OpenID authentication request: ' . (($immediate) ? 'immediate' : 'setup') . '; '. log_array($request));

    // Check for protocol correctness    
    if ($version == OPENID_VERSION_1_1) {
        if (!isset($request['openid.return_to'])) {
            log_error('Protocol Error: openid.return_to not set.');
            indirect_fatal_error(t('Protocol Error: openid.return_to not set.'));
            return;
        }
        if (!isset($request['openid.identity'])) {
            log_error('Protocol Error: openid.identity not set.');
            indirect_fatal_error(t('Protocol Error: openid.identity not set.'));
            return;
        }
    }

    if ($version >= OPENID_VERSION_2) {
        if (isset($request['openid.identity']) && !isset($request['openid.claimed_id'])) {
            log_error('Protocol Error: openid.identity set, but not openid.claimed_id.');
            indirect_fatal_error(t('Protocol Error: openid.identity set, but not openid.claimed_id.'));
            return;
        }
        
        if (!isset($request['openid.realm']) && !isset($request['openid.return_to'])) {
            log_error('Protocol Error: openid.return_to not set when openid.realm is not set.');
            indirect_fatal_error(t('Protocol Error: openid.return_to not set when openid.realm is not set.'));
            return;
        }
    }
    
    if (isset($request['openid.return_to'])) {
        $realm = openid_get_realm($request, $version);
        
        if (!openid_url_matches_realm($request['openid.return_to'], $realm)) {
            log_error('Protocol Error: openid.return_to does not match realm.');
            openid_indirect_error($request['openid.return_to'], 'Protocol Error: openid.return_to does not match realm.');
            return;
        }
    }
    
    if (isset($request['openid.identity'])) {
        // Standard request
        log_debug('openid.identity found, use simpleid_checkid_identity');
        $result = simpleid_checkid_identity($request, $immediate);
    } else {
        log_debug('openid.identity not found, trying extensions');
        // Extension request
        $results = extension_invoke_all('checkid', $request, $immediate);
        
        // Filter out nulls
        $results = array_merge(array_diff($results, array(NULL)));
        
        // If there are still results, it is the lowest value, otherwise, it is CHECKID_PROTOCOL_ERROR
        $result = ($results) ? min($results) : CHECKID_PROTOCOL_ERROR;
    }
    
    switch ($result) {
        case CHECKID_APPROVAL_REQUIRED:
            log_info('CHECKID_APPROVAL_REQUIRED');
            if ($immediate) {
                $response = simpleid_checkid_approval_required($request);
                simpleid_assertion_response($response, $request['openid.return_to']);
            } else {
                $response = simpleid_checkid_ok($request);
                simpleid_openid_consent_form($request, $response, $result);
            }
            break;
        case CHECKID_RETURN_TO_SUSPECT:
            log_info('CHECKID_RETURN_TO_SUSPECT');
            if ($immediate) {
                $response = simpleid_checkid_error($request, $immediate);
                simpleid_assertion_response($response, $request['openid.return_to']);
            } else {
                $response = simpleid_checkid_ok($request);
                simpleid_openid_consent_form($request, $response, $result);
            }
            break;
        case CHECKID_OK:
            log_info('CHECKID_OK');
            $response = simpleid_checkid_ok($request);
            $response = simpleid_sign($response, isset($request['openid.assoc_handle']) ? $request['openid.assoc_handle'] : NULL);
            simpleid_assertion_response($response, $request['openid.return_to']);
            break;
        case CHECKID_LOGIN_REQUIRED:
            log_info('CHECKID_LOGIN_REQUIRED');
            if ($immediate) {
                $response = simpleid_checkid_login_required($request);
                simpleid_assertion_response($response, $request['openid.return_to']);
            } else {
                user_login_form('continue', pickle($request));
                exit;
            }
            break;
        case CHECKID_IDENTITIES_NOT_MATCHING:
        case CHECKID_IDENTITY_NOT_EXIST:
            log_info('CHECKID_IDENTITIES_NOT_MATCHING | CHECKID_IDENTITY_NOT_EXIST');
            $response = simpleid_checkid_error($request, $immediate);
            if ($immediate) {                
                simpleid_assertion_response($response, $request['openid.return_to']);
            } else {                
                simpleid_openid_consent_form($request, $response, $result);                
            }
            break;
        case CHECKID_PROTOCOL_ERROR:
            if (isset($request['openid.return_to'])) {
                $response = simpleid_checkid_error($request, $immediate);
                simpleid_assertion_response($response, $request['openid.return_to']);
            } else {
                indirect_fatal_error('Unrecognised request.');
            }
            break;
    }
}

/**
 * Processes a standard OpenID authentication request about an identity.
 *
 * Checks whether the current user logged into SimpleID matches the identity
 * supplied in an OpenID request.
 *
 * @param array &$request the OpenID request
 * @param bool $immediate whether checkid_immediate was used
 * @return int one of CHECKID_OK, CHECKID_APPROVAL_REQUIRED, CHECKID_RETURN_TO_SUSPECT, CHECKID_IDENTITY_NOT_EXIST,
 * CHECKID_IDENTITIES_NOT_MATCHING, CHECKID_LOGIN_REQUIRED or CHECKID_PROTOCOL_ERROR
 * @global array the current logged in user
 */
function simpleid_checkid_identity(&$request, $immediate) {
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
        
        log_info('OpenID identifier selection: Selected ' . $uid . ' [' . $identity . ']');
    } else {
        $identity = $request['openid.identity'];
        $test_user = user_load_from_identity($identity);
    }
    if ($test_user == NULL) return CHECKID_IDENTITY_NOT_EXIST;
    if ($test_user['uid'] != $user['uid']) {
        log_notice('Requested user ' . $test_user['uid'] . ' does not match logged in user ' . $user['uid']);
        return CHECKID_IDENTITIES_NOT_MATCHING;
    }
    
    // Pass the assertion to extensions
    $assertion_results = extension_invoke_all('checkid_identity', $request, $identity, $immediate);
    $assertion_results = array_merge(array_diff($assertion_results, array(NULL)));
    
    // Populate the request with the selected identity
    if ($request['openid.identity'] == OPENID_IDENTIFIER_SELECT) {
        $request['openid.claimed_id'] = $identity;
        $request['openid.identity'] = $identity;
    }
    
    // Check 3: Discover the realm and match its return_to
    $user_rp = (isset($user['rp'][$realm])) ? $user['rp'][$realm] : NULL;

    if (($version >= OPENID_VERSION_2) && SIMPLEID_VERIFY_RETURN_URL_USING_REALM) {
        $verified = FALSE;
        
        $rp_info = simpleid_get_rp_info($realm);
        $services = discovery_xrds_services_by_type($rp_info['services'], OPENID_RETURN_TO);
        
        log_info('OpenID 2 discovery: ' . count($services) . ' matching services');
        
        if ($services) {
            $return_to_uris = array();
            
            foreach ($services as $service) {
                $return_to_uris = array_merge($return_to_uris, $service['uri']);
            }
            foreach ($return_to_uris as $return_to) {
                if (openid_url_matches_realm($request['openid.return_to'], $return_to)) {
                    log_info('OpenID 2 discovery: verified');
                    $verified = TRUE;
                    break;
                }
            }
        }
        
        $rp_info['return_to_verified'] = $verified;
        simpleid_set_rp_info($realm, $rp_info);
        
        if (!$verified) {
            if (($user_rp != NULL) && ($user_rp['auto_release'] == 1)) {
                log_notice('OpenID 2 discovery: not verified, but overridden by user preference');
            } else {
                log_notice('OpenID 2 discovery: not verified');
                $assertion_results[] = CHECKID_RETURN_TO_SUSPECT;
            }
        }
    }
    
    // Check 4: For checkid_immediate, the user must already have given
    // permission to log in automatically.    
    if (($user_rp != NULL) && ($user_rp['auto_release'] == 1)) {
        log_info('Automatic set for realm ' . $realm);
        $assertion_results[] = CHECKID_OK;
        return min($assertion_results);
    } else {
        $assertion_results[] = CHECKID_APPROVAL_REQUIRED;
        return min($assertion_results);
    }
}

/**
 * Obtains information on a relying party by performing discovery on them.  Information
 * obtained includes the discovery URL, the parsed XRDS document, and any other
 * information saved by SimpleID extensions
 *
 * The results are cached for 1 hour.  For performance reasons, stale results may
 * be obtained by using the $allow_stale parameter
 *
 * @param string $realm the openid.realm parameter
 * @param bool $allow_stale allow stale results to be returned, otherwise discovery
 * will occur
 * @return array containing information on a relying party.
 * @link http://openid.net/specs/openid-authentication-2_0.html#rp_discovery
 * @since 0.8
 */
function simpleid_get_rp_info($realm, $allow_stale = FALSE) {
    $url = openid_realm_discovery_url($realm);
    
    log_info('simpleid_get_rp_info');
    
    $rp_info = cache_get('rp-info', $realm);
    
    if (($rp_info == NULL) || (!isset($rp_info['updated'])) || (!$allow_stale && ($rp_info['updated'] < time() - 3600))) {
        log_info('OpenID 2 RP discovery: realm: ' . $realm . '; url: ' . $url);
        
        $rp_info = array(
            'url' => $url,
            'services' => discovery_xrds_discover($url),
            'updated' => time()
        );
        
        cache_set('rp-info', $realm, $rp_info);
    }

    return $rp_info;
}

/**
 * Saves information on a relying party to disk.
 *
 * @param string $realm the openid.realm parameter
 * @param array $rp_info containing information on a relying party.
 *
 * @since 0.8
 */
function simpleid_set_rp_info($realm, $rp_info) {
    if (!isset($rp_info['updated'])) $rp_info['updated'] = time();
    cache_set('rp-info', $realm, $rp_info, $rp_info['updated']);
}

/**
 * Returns an OpenID response indicating a positive assertion.
 *
 * @param array $request the OpenID request
 * @return array an OpenID response with a positive assertion
 * @link http://openid.net/specs/openid-authentication-1_1.html#anchor17, http://openid.net/specs/openid-authentication-1_1.html#anchor23, http://openid.net/specs/openid-authentication-2_0.html#positive_assertions
 */
function simpleid_checkid_ok($request) {
    global $version;
    
    $message = array(
        'openid.mode' => 'id_res',
        'openid.op_endpoint' => simpleid_url(),
        'openid.response_nonce' => openid_nonce()
    );
    
    if (isset($request['openid.assoc_handle'])) $message['openid.assoc_handle'] = $request['openid.assoc_handle'];
    if (isset($request['openid.identity'])) $message['openid.identity'] = $request['openid.identity'];
    if (isset($request['openid.return_to'])) $message['openid.return_to'] = $request['openid.return_to'];
    
    if (($version >= OPENID_VERSION_2) && isset($request['openid.claimed_id'])) {
        $message['openid.claimed_id'] = $request['openid.claimed_id'];
    }
    
    $message = array_merge($message, extension_invoke_all('response', TRUE, $request));
    
    log_info('OpenID authentication response: ' . log_array($message));
    return openid_indirect_message($message, $version);
}

/**
 * Returns an OpenID response indicating a negative assertion to a
 * checkid_immediate request, where an approval of the relying party by the
 * user is required
 *
 * @param mixed $request the OpenID request
 * @return mixed an OpenID response with a negative assertion
 * @link http://openid.net/specs/openid-authentication-1_1.html#anchor17, http://openid.net/specs/openid-authentication-1_1.html#anchor23, http://openid.net/specs/openid-authentication-2_0.html#negative_assertions
 */
function simpleid_checkid_approval_required($request) {
    global $version;
    
    if ($version >= OPENID_VERSION_2) {
        $message = array('openid.mode' => 'setup_needed');
    } else {
        $request['openid.mode'] = 'checkid_setup';
        $message = array(
            'openid.mode' => 'id_res',            
            'openid.user_setup_url' => simpleid_url('continue', 's=' . rawurlencode(pickle($request)))
        );
    }
    
    $message = array_merge($message, extension_invoke_all('response', FALSE, $request));
    
    log_info('OpenID authentication response: ' . log_array($message));
    return openid_indirect_message($message, $version);
}

/**
 * Returns an OpenID response indicating a negative assertion to a
 * checkid_immediate request, where the user has not logged in.
 *
 * @param array $request the OpenID request
 * @return array an OpenID response with a negative assertion
 * @link http://openid.net/specs/openid-authentication-1_1.html#anchor17, http://openid.net/specs/openid-authentication-1_1.html#anchor23, http://openid.net/specs/openid-authentication-2_0.html#negative_assertions
 */
function simpleid_checkid_login_required($request) {
    global $version;
    
    if ($version >= OPENID_VERSION_2) {
        $message = array('openid.mode' => 'setup_needed');
    } else {    
        $message = array(
            'openid.mode' => 'id_res',
            'openid.user_setup_url' => simpleid_url('login', 'destination=continue&s=' . rawurlencode(pickle($request)))
        );
    }
    
    $message = array_merge($message, extension_invoke_all('response', FALSE, $request));
    
    log_info('OpenID authentication response: ' . log_array($message));
    return openid_indirect_message($message, $version);
}

/**
 * Returns an OpenID response indicating a generic negative assertion.
 *
 * The content of the negative version depends on the OpenID version, and whether
 * the openid.mode of the request was checkid_immediate
 *
 * @param array $request the OpenID request
 * @param bool $immediate true if openid.mode of the request was checkid_immediate
 * @return array an OpenID response with a negative assertion
 * @link http://openid.net/specs/openid-authentication-1_1.html#anchor17, http://openid.net/specs/openid-authentication-1_1.html#anchor23, http://openid.net/specs/openid-authentication-2_0.html#negative_assertions
 */
function simpleid_checkid_error($request, $immediate = false) {
    global $version;
    
    $message = array();
    if ($immediate) {
        if ($version >= OPENID_VERSION_2) {
            $message['openid.mode'] = 'setup_needed';
        } else {
            $message['openid.mode'] = 'id_res';
        }
    } else {
        $message['openid.mode'] = 'cancel';
    }
    
    $message = array_merge($message, extension_invoke_all('response', FALSE, $request));
    
    log_info('OpenID authentication response: ' . log_array($message));
    return openid_indirect_message($message, $version);
}

/**
 * Signs an OpenID response, using signature information from an association
 * handle.
 *
 * @param array &$response the OpenID response
 * @param array $assoc_handle the association handle containing key information
 * for the signature.  If $assoc_handle is not specified, a private association
 * is created
 * @return array the signed OpenID response
 *
 */
function simpleid_sign(&$response, $assoc_handle = NULL) {
    global $version;
    
    if (!$assoc_handle) {
        $assoc = _simpleid_create_association(ASSOCIATION_PRIVATE);
        $response['openid.assoc_handle'] = $assoc['assoc_handle'];
    } else {
        $assoc = cache_get('association', $assoc_handle);
        
        if ($assoc['created'] + SIMPLEID_ASSOC_EXPIRES_IN < time()) {
            // Association has expired, need to create a new one
            log_notice('Association handle ' . $assoc['assoc_handle'] . ' expired.  Using stateless mode.');
            $response['openid.invalidate_handle'] = $assoc_handle;
            $assoc = _simpleid_create_association(ASSOCIATION_PRIVATE);
            $response['openid.assoc_handle'] = $assoc['assoc_handle'];
        }
    }
    
    // If we are using stateless mode, then we need to cache the response_nonce
    // so that the RP can only verify once
    if (isset($assoc['private']) && ($assoc['private'] == 1) && isset($response['openid.response_nonce'])) {
        cache_set('stateless', $response['openid.response_nonce'], array(
            'response_nonce' => $response['openid.response_nonce'],
            'assoc_handle' => $response['openid.assoc_handle']));
    }
    
    // Get all the signed fields [10.1]
    openid_parse_request($response); // Fill the namespace array
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
    
    $response['openid.sig'] = openid_sign($response, $to_sign, $mac_key, $hmac_func, $version);
    
    log_info('OpenID signed authentication response: ' . log_array($response));
    
    return $response;
}

/**
 * Processes a direct verification request.  This is used in the OpenID specification
 * to verify signatures generated using stateless mode.
 *
 * @param array $request the OpenID request
 * @see http://openid.net/specs/openid-authentication-1_1.html#mode_check_authentication, http://openid.net/specs/openid-authentication-2_0.html#verifying_signatures
 */
function simpleid_check_authentication($request) {
    global $version;
    
    log_info('OpenID direct verification: ' . log_array($request));
    
    $is_valid = simpleid_verify_signatures($request);

    if ($is_valid) {
        $response = array('is_valid' => 'true');
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

    log_info('OpenID direct verification response: ' . log_array($response));
    
    openid_direct_response(openid_direct_message($response, $version));
}

/**
 * Verifies the signature of a signed OpenID request/response.
 *
 * @param array $request the OpenID request/response
 * @return bool true if the signature is verified
 * @since 0.8
 */
function simpleid_verify_signatures($request) {
    global $version;
    
    log_info('simpleid_verify_signatures');
    
    $is_valid = TRUE;
  
    $assoc = (isset($request['openid.assoc_handle'])) ? cache_get('association', $request['openid.assoc_handle']) : NULL;
    $stateless = (isset($request['openid.response_nonce'])) ? cache_get('stateless', $request['openid.response_nonce']) : NULL;
  
    if (!$assoc) {
        log_notice('simpleid_verify_signatures: Association not found.');
        $is_valid = FALSE;
    } elseif (!$assoc['assoc_type']) {
        log_error('simpleid_verify_signatures: Association does not contain valid assoc_type.');
        $is_valid = FALSE;
    } elseif (!isset($assoc['private']) || ($assoc['private'] != 1)) {
        log_warn('simpleid_verify_signatures: Attempting to verify an association with a shared key.');
        $is_valid = FALSE;
    } elseif (!$stateless || ($stateless['assoc_handle'] != $request['openid.assoc_handle'])) {
        log_warn('simpleid_verify_signatures: Attempting to verify a response_nonce more than once, or private association expired.');
        $is_valid = FALSE;
    } else {
        $mac_key = $assoc['mac_key'];
        $assoc_types = openid_association_types();
        $hmac_func = $assoc_types[$assoc['assoc_type']]['hmac_func'];
        
        $signed_keys = explode(',', $request['openid.signed']);
        $signature = openid_sign($request, $signed_keys, $mac_key, $hmac_func, $version);
        log_debug('***** Signature: ' . $signature);
        
        if ($signature != $request['openid.sig']) {
            log_warn('simpleid_verify_signatures: Signature supplied in request does not match the signatured generated.');
            $is_valid = FALSE;
        }
        
        cache_delete('stateless', $request['openid.response_nonce']);
    }
    
    return $is_valid;
}


/**
 * Continues an OpenID authentication request.
 *
 * This function decodes an OpenID authentication request specified in the
 * s request parameter and feeds it to the
 * {@link simpleid_process_openid} function.  This allows SimpleID to preserve
 * the state of an OpenID request.
 */
function simpleid_continue() {
    global $GETPOST;
    
    $request = unpickle($GETPOST['s']);
    openid_parse_request($request);
    simpleid_process_openid($request);
}

/**
 * Provides a form for user consent of an OpenID relying party, where the 
 * {@link simpleid_checkid_identity()} function returns a CHECKID_APPROVAL_REQUIRED
 * or CHECKID_RETURN_TO_SUSPECT.
 *
 * Alternatively, provide a form for the user to rectify the situation where
 * {@link simpleid_checkid_identity()} function returns a CHECKID_IDENTITIES_NOT_MATCHING
 * or CHECKID_IDENTITY_NOT_EXIST
 *
 * @param array $request the original OpenID request
 * @param array $response the proposed OpenID response, subject to user
 * verification
 * @param int $reason either CHECKID_APPROVAL_REQUIRED, CHECKID_RETURN_TO_SUSPECT,
 * CHECKID_IDENTITIES_NOT_MATCHING or CHECKID_IDENTITY_NOT_EXIST
 */
function simpleid_openid_consent_form($request, $response, $reason = CHECKID_APPROVAL_REQUIRED) {
    global $user;
    global $xtpl;
    global $version;
    
    $request_state = pickle($request);
    
    user_header($request_state);

    $realm = openid_get_realm($request, $version);
    
    $xtpl->assign('token', get_form_token('rp'));
    $xtpl->assign('state', pickle($response));
    $xtpl->assign('realm', htmlspecialchars($realm, ENT_QUOTES, 'UTF-8'));
    
    $xtpl->assign('cancel_button', t('Cancel'));

    if ($response['openid.mode'] == 'cancel') {
        $xtpl->assign('return_to', htmlspecialchars($request['openid.return_to'], ENT_QUOTES, 'UTF-8'));
        
        $xtpl->assign('unable_label', t('Unable to log into <strong class="realm">@realm</strong>.', array('@realm' => $realm)));
        $xtpl->assign('identity_not_matching_label', t('Your current identity does not match the requested identity %identity.', array('%identity' => $request['openid.identity'])));
        $xtpl->assign('switch_user_label', t('<a href="!url">Switch to a different user</a> and try again.', array('!url' => simpleid_url('logout', 'destination=continue&s=' . rawurlencode($request_state), true))));
        
        $xtpl->parse('main.openid_consent.cancel');
    } else {
        $xtpl->assign('javascript', '<script src="' . get_base_path() . 'html/openid-consent.js" type="text/javascript"></script>');
        
        $rp = (isset($user['rp'][$realm])) ? $user['rp'][$realm] : NULL;
        
        $extensions = extension_invoke_all('consent_form', $request, $response, $rp);
        $xtpl->assign('extensions', implode($extensions));
        
        if ($reason == CHECKID_RETURN_TO_SUSPECT) {
            $xtpl->assign('suspect_label', t('Warning: This web site has not confirmed its identity and might be fraudulent.  Do not share any personal information with this web site unless you are sure it is legitimate. See the <a href="!url" class="popup">SimpleID documentation for details</a> (OpenID version 2.0 return_to discovery failure)',
                array('!url' => 'http://simpleid.koinic.net/documentation/troubleshooting/returnto-discovery-failure')));
            
            $xtpl->parse('main.openid_consent.setup.suspect');
            $xtpl->assign('realm_class', 'return-to-suspect');
        }
        
        $xtpl->assign('realm_label', t('You are being logged into <strong class="realm">@realm</strong>.', array('@realm' => $realm)));
        $xtpl->assign('auto_release_label', t('Automatically send my information to this site for any future requests.'));
        $xtpl->assign('ok_button', t('OK'));
        
        $xtpl->parse('main.openid_consent.setup');
    }
    
    $xtpl->parse('main.openid_consent');
    
    $xtpl->assign(array('js_locale_label' => 'openid_suspect', 'js_locale_text' => addslashes(t('This web site has not confirmed its identity and might be fraudulent.')) . '\n\n' . addslashes(t('Are you sure you wish to automatically send your information to this site for any future requests?'))));
    $xtpl->parse('main.js_locale');
    
    $xtpl->parse('main.framekiller');
    
    header('X-Frame-Options: DENY');
    
    $xtpl->assign('title', t('OpenID Login'));
    $xtpl->assign('page_class', 'dialog-page');
    $xtpl->parse('main');
    
    $xtpl->out('main');
}


/**
 * Processes a user response from the {@link simpleid_openid_consent_form()} function.
 *
 * If the user verifies the relying party, an OpenID response will be sent to
 * the relying party.  Otherwise, the dashboard will be displayed to the user.
 *
 */
function simpleid_openid_consent() {
    global $xtpl, $user, $version, $GETPOST;
    
    if ($user == NULL) {
        user_login_form('');
        return;
    }
    
    if (!validate_form_token($GETPOST['tk'], 'rp')) {
        set_message(t('SimpleID detected a potential security attack.  Please try again.'));
        $xtpl->assign('title', t('OpenID Login'));
        $xtpl->parse('main');
        $xtpl->out('main');
        return;
    }
    
    $uid = $user['uid'];
    
    $response = unpickle($GETPOST['s']);
    $version = openid_get_version($response);
    openid_parse_request($response);
    $return_to = $response['openid.return_to'];
    if (!$return_to) $return_to = $GETPOST['openid.return_to'];
    
    if ($GETPOST['op'] == t('Cancel')) {
        $response = simpleid_checkid_error(false);
        if (!$return_to) set_message(t('Log in cancelled.'));
    } else {
        $now = time();
        $realm = $GETPOST['openid.realm'];
        
        if (isset($user['rp'][$realm])) {
            $rp = $user['rp'][$realm];
        } else {
            $rp = array('realm' => $realm, 'first_time' => $now);
        }
        $rp['last_time'] = $now;
        $rp['auto_release'] = (isset($GETPOST['autorelease']) && $GETPOST['autorelease']) ? 1 : 0;
        
        // Mimic extension_invoke_all, but allow for passing by reference {{
        global $simpleid_extensions;
    
        foreach ($simpleid_extensions as $extension) {
            $consent_function = $extension . '_consent';
            if (function_exists($consent_function)) {
                $consent_function($GETPOST, $response, $rp);
            }
        }
        // }}
        
        $user['rp'][$realm] = $rp;
        user_save($user);
        
        $response = simpleid_sign($response, isset($response['openid.assoc_handle']) ? $response['openid.assoc_handle'] : NULL);
        if (!$return_to) set_message(t('You were logged in successfully.'));
    }

    if ($return_to) {
        simpleid_assertion_response($response, $return_to);
    } else {
        page_dashboard();
    }
}

/**
 * Sends an OpenID assertion response.
 *
 * The OpenID specification version 2.0 provides for the sending of assertions
 * via indirect communication.  However, future versions of the OpenID
 * specification may provide for sending of assertions via direct communication.
 *
 * @param array $response the signed OpenID assertion response to send
 * @param string $indirect_url the URL to which the OpenID response is sent.  If
 * this is an empty string, the response is sent via direct communication
 */
function simpleid_assertion_response($response, $indirect_url = NULL) {
    global $xtpl, $version;
    
    if ($indirect_url) {
        // We want to see if the extensions want to change the way indirect responses are made
        $results = extension_invoke_all('indirect_response', $indirect_url, $response);
        $results = array_filter($results, 'is_null');
        $component = ($results) ? max($results) : OPENID_RESPONSE_QUERY;
        
        openid_indirect_response($indirect_url, $response, $component);
    } else {
        openid_direct_response(openid_direct_message($response, $version));
    }
}

/**
 * Displays the XRDS document for this SimpleID installation.
 * 
 */
function simpleid_xrds() {
    global $xtpl;
    
    log_debug('Providing XRDS.');
    
    header('Content-Type: application/xrds+xml');
    header('Content-Disposition: inline; filename=yadis.xml');
    
    $types = extension_invoke_all('xrds_types');
    foreach ($types as $type) {
        $xtpl->assign('uri', htmlspecialchars($type, ENT_QUOTES, 'UTF-8'));
        $xtpl->parse('xrds.op_xrds.type');
    }
    
    $xtpl->assign('simpleid_base_url', htmlspecialchars(simpleid_url(), ENT_QUOTES, 'UTF-8'), false, 'detect');
    $xtpl->parse('xrds.op_xrds');
    $xtpl->parse('xrds');
    $xtpl->out('xrds');
}


?>
