<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007-9
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
 * Implements the popup mode from the User Interface extension
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
    return array('http://specs.openid.net/extensions/ui/1.0/mode/popup');
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
 * @see hook_rp_form()
 */
function ui_rp_form($request, $response, $rp) {
    // Skip if popup does not exist
    if (!openid_extension_requested(OPENID_NS_UI, $request)) return '';
    
    $filtered_request = openid_extension_filter_request(OPENID_NS_UI, $request);
    
    if (isset($filtered_request['mode']) && ($filtered_request['mode'] == 'popup')) _ui_insert_css_js();
    
    return '';
}

/**
 * Inserts the necessary CSS and JavaScript code to implement the popup mode
 * from the User Interface extension.
 */
function _ui_insert_css_js() {
    global $xtpl;
    
    $css = (isset($xtpl->vars['css'])) ? $xtpl->vars['css'] : '';
    $js = (isset($xtpl->vars['javascript'])) ? $xtpl->vars['javascript'] : '';
    
    $xtpl->assign('css', $css . '@import url(extensions/ui/ui.css);');
    $xtpl->assign('javascript', $js . '<script src="extensions/ui/ui.js" type="text/javascript"></script>');
}

?>
