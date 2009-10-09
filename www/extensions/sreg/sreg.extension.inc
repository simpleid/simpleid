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
 * Implements the Simple Registration extension.
 * 
 *
 * @package simpleid
 * @subpackage extensions
 * @filesource
 */
 


/**
 * @see hook_response()
 */
function sreg_response($assertion, $request) {
    global $user;
    global $version;
    
    // We only deal with positive assertions
    if (!$assertion) return array();
    
    // We only respond if the extension is requested
    if (!openid_extension_requested('http://openid.net/extensions/sreg/1.1', $request)) return array();
    
    $request = openid_extension_filter_request('http://openid.net/extensions/sreg/1.1', $request);
    $required = (isset($request['required'])) ? explode(',', $request['required']) : array();
    $optional = (isset($request['optional'])) ? explode(',', $request['optional']) : array();
    $fields = array_merge($required, $optional);
    $alias = openid_extension_alias('http://openid.net/extensions/sreg/1.1');
    $response = array();
    
    if ($version == OPENID_VERSION_2) $response['openid.ns.' . $alias] = 'http://openid.net/extensions/sreg/1.1';
    
    foreach ($fields as $field) {
        if (isset($user['sreg'][$field])) {
            $response['openid.' . $alias . '.' .  $field] = $user['sreg'][$field];
        }
    }
    
    return $response;
}

/**
 * Returns an array of fields that need signing.
 *
 * @see hook_signed_fields()
 */
function sreg_signed_fields($response) {
    // We only respond if the extension is requested
    if (!openid_extension_requested('http://openid.net/extensions/sreg/1.1', $response)) return array();
    
    $fields = array_keys(openid_extension_filter_request('http://openid.net/extensions/sreg/1.1', $response));
    $alias = openid_extension_alias('http://openid.net/extensions/sreg/1.1');
    $signed_fields = array();

    foreach ($fields as $field) {
        if (isset($response['openid.' . $alias . '.' . $field])) $signed_fields[] = $alias . '.' . $field;
    }
    
    return $signed_fields;
}

/**
 * @see hook_rp_form()
 */
function sreg_rp_form($request, $response, $rp) {
    global $user;
    
    // We only respond if the extension is requested
    if (!openid_extension_requested('http://openid.net/extensions/sreg/1.1', $request)) return '';
    
    $request = openid_extension_filter_request('http://openid.net/extensions/sreg/1.1', $request);
    $required = (isset($request['required'])) ? explode(',', $request['required']) : array();
    $optional = (isset($request['optional'])) ? explode(',', $request['optional']) : array();
    $keys = array_merge($required, $optional);
    
    if ((count($request)) && isset($user['sreg'])) {
        $xtpl2 = new XTemplate('extensions/sreg/sreg.xtpl');
        
        $xtpl2->assign('alias', openid_extension_alias('http://openid.net/extensions/sreg/1.1'));
        
        if (isset($request['policy_url'])) {            
            $xtpl2->assign('policy', 'You can view the site\'s policy in relation to the use of this information at this URL: <a href="' . htmlspecialchars($request['policy_url'], ENT_QUOTES, 'UTF-8') . '">' . htmlspecialchars($request['policy_url'], ENT_QUOTES, 'UTF-8') . '</a>.');            
        }
        
        foreach ($keys as $key) {
            if (isset($user['sreg'][$key])) {
                $xtpl2->assign('name', htmlspecialchars($key, ENT_QUOTES, 'UTF-8'));
                $xtpl2->assign('value', htmlspecialchars($user['sreg'][$key], ENT_QUOTES, 'UTF-8'));
                $xtpl2->parse('form.sreg');
            }
        }
        
        $xtpl2->parse('form');
        return $xtpl2->text('form');
    }
}

/**
 * @see hook_page_profile()
 */
function sreg_page_profile() {
    global $user;
    $xtpl2 = new XTemplate('extensions/sreg/sreg.xtpl');
    
    if (isset($user['sreg'])) {
        foreach ($user['sreg'] as $name => $value) {
            $xtpl2->assign('name', htmlspecialchars($name, ENT_QUOTES, 'UTF-8'));
            $xtpl2->assign('value', htmlspecialchars($value, ENT_QUOTES, 'UTF-8'));
            $xtpl2->parse('user_page.sreg');
        }
    }    
    
    $xtpl2->parse('user_page');
    
    return array(array(
        'id' => 'sreg',
        'title' => 'Simple Registration Extension',
        'content' => $xtpl2->text('user_page')
    ));
}

?>
