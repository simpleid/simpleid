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

function sreg_ns() {
    return "http://openid.net/extensions/sreg/1.1";
}

function sreg_default_alias() {
    return "sreg";
}

function sreg_checkid_ok() {
    global $user;
    
    $request = extension_get_request(sreg_ns(), $response);
    $required = explode(',', $request['required']);
    $optional = explode(',', $request['optional']);
    $keys = array_merge($required, $optional);
    $alias = extension_get_alias(sreg_ns());
    $return = array();
    
    foreach ($keys as $key) {
        if (isset($user['sreg'][$key])) {
            $return['openid.' . $alias . '.key'] = $user['sreg'][$key];
        }
    }
    
    return $return;
}

/**
 * Returns an array of keys that need signing.
 */
function sreg_signed_keys($response) {
    $request = extension_get_request(sreg_ns(), $response);
    $required = explode(',', $request['required']);
    $optional = explode(',', $request['optional']);
    $keys = array_merge($required, $optional);
    $alias = extension_get_alias(sreg_ns());
    $return = array();
    
    foreach ($keys as $key) {
        if (isset($response['openid.' . $alias . '.key'])) $return[] = $alias . '.' . $key;
    }
    
    return $return;
}

function sreg_form($form, $rp) {
    global $user;
    
    $request = extension_get_request(sreg_ns(), $form);
    $required = explode(',', $request['required']);
    $optional = explode(',', $request['optional']);
    $keys = array_merge($required, $optional);
    
    if ((count($request)) && isset($user['sreg'])) {
        $xtpl2 = new XTemplate('html/sreg.xtpl');
        
        $xtpl2->assign('alias', extension_get_alias(sreg_ns()));
        
        if (isset($request['policy_url'])) {
            $xtpl2->assign('policy', 'You can view the site\'s <a href="' & htmlspecialchars($request['policy_url']) & '">policy</a> in relation to the use of this information.');
        }
        
        foreach ($keys as $key) {
            if (isset($user['sreg'][$key])) {
                $xtpl2->assign('name', htmlspecialchars($key));
                $xtpl2->assign('value', htmlspecialchars($user['sreg'][$key]));
                $xtpl2->parse('form.sreg');
            }
        }
    }
    
    $xtpl2->parse('form');
    return $xtpl2->text('form');
}

function sreg_send() {
}

function sreg_user_page() {
    global $user;
    $xtpl2 = new XTemplate('html/sreg.xtpl');
    
    if (isset($user['sreg'])) {
        foreach ($user['sreg'] as $name => $value) {
            $xtpl2->assign('name', htmlspecialchars($name));
            $xtpl2->assign('value', htmlspecialchars($value));
            $xtpl2->parse('user_page.sreg');
        }
    }
    
    $xtpl2->parse('user_page');
    return $xtpl2->text('user_page');
}

?>
