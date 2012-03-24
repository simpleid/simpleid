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
 * Implements the popup and icon modes from the User Interface extension
 *
 * @package simpleid
 * @subpackage extensions
 * @filesource
 */

/** Namespace for the User Interface extension */
define('OPENID_NS_UI', 'http://specs.openid.net/extensions/ui/1.0');

/**
 * Returns the popup mode in SimpleID XRDS document
 *
 * @return array
 * @see hook_xrds_types()
 */
function ui_xrds_types() {
    return array(
        'http://specs.openid.net/extensions/ui/1.0/mode/popup',
        'http://specs.openid.net/extensions/ui/1.0/icon'
    );
}

/**
 * Detects the openid.ui.x-has-session parameter and processes it accordingly.
 *
 * @return array
 * @see hook_response()
 */
function ui_response($assertion, $request) {
    global $user;
    global $version;
    
    // We only deal with negative assertions
    if ($assertion) return array();
    
    // We only respond if the extension is requested
    if (!openid_extension_requested(OPENID_NS_UI, $request)) return array();
    
    // We only deal with openid.ui.x-has-session requests
    $filtered_request = openid_extension_filter_request(OPENID_NS_UI, $request);
    if (!isset($filtered_request['mode']) || ($filtered_request['mode'] != 'x-has-session')) return array();
    
    // If user is null, there is no active session
    if ($user == NULL) return array();
    
    // There is an active session
    $alias = openid_extension_alias(OPENID_NS_UI);
    $response = array();
    
    $response['openid.ns.' . $alias] = OPENID_NS_UI;
    $response['openid.' . $alias . '.mode'] = 'x-has-session';
    
    return $response;
}

/**
 * Returns an array of fields that need signing.
 *
 * @see hook_signed_fields()
 */
function ui_signed_fields($response) {
    // We only respond if the extension is requested
    if (!openid_extension_requested(OPENID_NS_UI, $response)) return array();
    
    $fields = array_keys(openid_extension_filter_request(OPENID_NS_UI, $response));
    $alias = openid_extension_alias(OPENID_NS_UI);
    $signed_fields = array();

    if (isset($response['openid.ns.' . $alias])) $signed_fields[] = 'ns.' . $alias;
    foreach ($fields as $field) {
        if (isset($response['openid.' . $alias . '.' . $field])) $signed_fields[] = $alias . '.' . $field;
    }
    
    return $signed_fields;
}

/**
 * Detects the presence of the UI extension and modifies the login form
 * accordingly.
 *
 * @param string $destination
 * @param string $state
 * @see hook_user_login_form()
 */
function ui_user_login_form($destination, $state) {
    if (($destination != 'continue') || (!$state)) return;
    
    $request = unpickle($state);
    openid_parse_request($request);
    
    // Skip if popup does not exist
    if (!openid_extension_requested(OPENID_NS_UI, $request)) return;
    
    $filtered_request = openid_extension_filter_request(OPENID_NS_UI, $request);
    
    if (isset($filtered_request['mode']) && ($filtered_request['mode'] == 'popup')) _ui_insert_css_js();
    
    return;
}

/**
 * Detects the presence of the UI extension and modifies the relying party
 * verification form accordingly.
 *
 * @param array $request
 * @param array $response
 * @param array $rp
 * @return string
 * @see hook_consent_form()
 */
function ui_consent_form($request, $response, $rp) {
    // Skip if popup does not exist
    if (!openid_extension_requested(OPENID_NS_UI, $request)) return '';
    
    $filtered_request = openid_extension_filter_request(OPENID_NS_UI, $request);
    
    if (isset($filtered_request['mode']) && ($filtered_request['mode'] == 'popup')) _ui_insert_css_js();
    
    if (isset($filtered_request['icon']) && ($filtered_request['icon'] == 'true')) {
        global $xtpl;
        
        $realm = $request['openid.realm'];
        $icon_url = simpleid_url('ui/icon', 'realm=' . rawurlencode($realm) . '&tk=' . _ui_icon_token($realm));
        
        $xtpl->assign('icon_url', htmlspecialchars($icon_url, ENT_QUOTES, 'UTF-8'));
        $xtpl->parse('main.openid_consent.icon');
    }
    
    return '';
}

/**
 * Specifies that the OpenID response should be sent via the fragment
 *
 */
function ui_indirect_response($url, $response) {
    global $openid_ns_to_alias;
    if (!array_key_exists(OPENID_NS_UI, $openid_ns_to_alias)) return NULL;
    
    // Cheat - if we run this, then the redirect page will also be themed!
    _ui_insert_css_js();
    
    if (strstr($url, '#')) {
        return OPENID_RESPONSE_FRAGMENT;
    } else {
        return NULL;
    }
}

/**
 * Adds an extra route to the SimpleWeb framework.
 */
function ui_routes() {
    return array('ui/icon' => 'ui_icon');
}

/**
 * Returns an icon.
 */
function ui_icon() {
    if (!isset($_GET['realm']) || !isset($_GET['tk']) || ($_GET['tk'] != _ui_icon_token($_GET['realm']))) {
        header_response_code('404 Not Found');
        indirect_fatal_error(t('Invalid UI icon parameters.'));
    }
    
    $realm = $_GET['realm'];
    $icon_res = _ui_get_icon($realm);
    
    if ($icon_res === NULL) {
        header_response_code('404 Not Found');
        indirect_fatal_error(t('Unable to get icon.'));
    }
    
    header('Via: ' . $icon_res['protocol'] . ' simpleid-ui-icon-' . md5($realm));
    header('Cache-Control: max-age=86400');
    header('Content-Type: ' . $icon_res['headers']['content-type']);
    if (isset($icon_res['headers']['content-encoding'])) header('Content-Encoding: ' . $icon_res['headers']['content-encoding']);
    print $icon_res['data'];
}

/**
 * Inserts the necessary CSS and JavaScript code to implement the popup mode
 * from the User Interface extension.
 */
function _ui_insert_css_js() {
    global $xtpl;
    
    $css = (isset($xtpl->vars['css'])) ? $xtpl->vars['css'] : '';
    $js = (isset($xtpl->vars['javascript'])) ? $xtpl->vars['javascript'] : '';
    
    $xtpl->assign('css', $css . '@import url(' . get_base_path() . 'extensions/ui/ui.css);');
    $xtpl->assign('javascript', $js . '<script src="' . get_base_path() . 'extensions/ui/ui.js" type="text/javascript"></script>');
}

/**
 * Attempts to obtain an icon from a RP
 *
 * @param string $realm the openid.realm parameter
 * @return array the response from {@link http_make_request()} with the discovered URL of the
 * RP's icon
 */
function _ui_get_icon($realm) {
    $rp_info = simpleid_get_rp_info($realm);
    
    if (isset($rp_info['ui_icon'])) return $rp_info['ui_icon'];
    
    $services = discovery_xrds_services_by_type($rp_info['services'], 'http://specs.openid.net/extensions/ui/icon');
        
    if ($services) {
        $icon_url = $services[0]['uri'];
        
        $icon_res = http_make_request($icon_url);
        if (isset($icon_res['http-error'])) {
            return NULL;
        }
        
        $rp_info['ui_icon'] = $icon_res;
        simpleid_set_rp_info($realm, $rp_info);
    } else {
        return NULL;
    }
}

/**
 * Returns a token to be used when requesting the icon.
 *
 * The token is used to prevent flooding SimpleID with external requests.
 *
 * @param string $realm the openid.realm parameter
 * @return string the token
 */
function _ui_icon_token($realm) {
    return get_form_token('q=ui/icon&realm=' . rawurlencode($realm));
}
?>
