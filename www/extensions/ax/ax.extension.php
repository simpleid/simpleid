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
 * Implements the Attribute Exchange extension.
 * 
 *
 * @package simpleid
 * @subpackage extensions
 * @filesource
 */

/** Namespace for the AX extension */
define('OPENID_NS_AX', 'http://openid.net/srv/ax/1.0');

/** @ignore */
global $ax_sreg_map;

/**
 * A mapping between Type URIs defined for Attribute Exchange and the corresponding
 * property for the Simple Registration Extension
 *
 * @link http://www.axschema.org/types/#sreg
 * @global array
 */
$ax_sreg_map = array(
    'http://axschema.org/namePerson/friendly' => 'nickname',
    'http://axschema.org/contact/email' => 'email',
    'http://axschema.org/namePerson' => 'fullname',
    'http://axschema.org/birthDate' => 'dob',
    'http://axschema.org/person/gender' => 'gender',
    'http://axschema.org/contact/postalCode/home' => 'postcode',
    'http://axschema.org/contact/country/home' => 'country',
    'http://axschema.org/pref/language' => 'language',
    'http://axschema.org/pref/timezone' => 'timezone',
    'http://openid.net/schema/namePerson/friendly' => 'nickname',
    'http://openid.net/schema/contact/internet/email' => 'email',
    'http://openid.net/schema/gender' => 'gender',
    'http://openid.net/schema/contact/postalCode/home' => 'postcode',
    'http://openid.net/schema/contact/country/home' => 'country',
    'http://openid.net/schema/language/pref' => 'language',
    'http://openid.net/schema/timezone' => 'timezone'
);

/**
 * Returns the support for AX in SimpleID XRDS document
 *
 * @return array
 * @see hook_xrds_types()
 */
function ax_xrds_types() {
    return array(OPENID_NS_AX);
}

/**
 * @see hook_response()
 */
function ax_response($assertion, $request) {
    global $user;
    global $version;
    global $ax_sreg_map;
    
    // We only deal with positive assertions
    if (!$assertion) return array();
    
    // We only respond if the extension is requested
    if (!openid_extension_requested(OPENID_NS_AX, $request)) return array();
    
    $request = openid_extension_filter_request(OPENID_NS_AX, $request);
    if (!isset($request['mode'])) return array();
    $mode = $request['mode'];
    
    $response = array();
    $alias = openid_extension_alias(OPENID_NS_AX);
    $response['openid.ns.' . $alias] = OPENID_NS_AX;
    
    if ($mode == 'fetch_request') {
        $response['openid.' . $alias . '.mode'] = 'fetch_response';
        
        $required = (isset($request['required'])) ? explode(',', $request['required']) : array();
        $optional = (isset($request['if_available'])) ? explode(',', $request['if_available']) : array();
        $fields = array_merge($required, $optional);
        
        foreach ($fields as $field) {
            $type = $request['type.' . $field];
            $response['openid.' . $alias . '.type.' . $field] = $type;
            $value = _ax_get_value($type);
            
            if ($value == NULL) {
                $response['openid.' . $alias . '.count.' .  $field] = 0;
            } elseif (is_array($value)) {
                $response['openid.' . $alias . '.count.' .  $field] = count($value);
                for ($i = 0; $i < count($value); $i++) {
                    $response['openid.' . $alias . '.value.' .  $field . '.' . ($i + 1)] = $value[$i];
                }
            } else {
                $response['openid.' . $alias . '.value.' .  $field] = $value;
            }
        }
    } elseif ($mode == 'store_request') {
        // Sadly, we don't support storage at this stage
        $response['openid.' . $alias . '.mode'] = 'store_response_failure';
        $response['openid.' . $alias . '.error'] = 'OpenID provider does not support storage of attributes';
    }
    
    return $response;
}

/**
 * Returns an array of fields that need signing.
 *
 * @see hook_signed_fields()
 */
function ax_signed_fields($response) {
    // We only respond if the extension is requested
    if (!openid_extension_requested(OPENID_NS_AX, $response)) return array();
    
    $fields = array_keys(openid_extension_filter_request(OPENID_NS_AX, $response));
    $alias = openid_extension_alias(OPENID_NS_AX);
    $signed_fields = array();

    if (isset($response['openid.ns.' . $alias])) $signed_fields[] = 'ns.' . $alias;
    foreach ($fields as $field) {
        if (isset($response['openid.' . $alias . '.' . $field])) $signed_fields[] = $alias . '.' . $field;
    }
    
    return $signed_fields;
}

/**
 * @see hook_consent_form()
 */
function ax_consent_form($request, $response, $rp) {
    global $user;
    
    // We only respond if the extension is requested
    if (!openid_extension_requested(OPENID_NS_AX, $request)) return '';
    
    $request = openid_extension_filter_request(OPENID_NS_AX, $request);
    if (!isset($request['mode'])) return '';
    $mode = $request['mode'];
    
    $xtpl2 = new XTemplate('extensions/ax/ax.xtpl');
    
    if ($mode == 'fetch_request') {
        $xtpl2->assign('alias', openid_extension_alias(OPENID_NS_AX));
        
        $required = (isset($request['required'])) ? explode(',', $request['required']) : array();
        $optional = (isset($request['if_available'])) ? explode(',', $request['if_available']) : array();
        $fields = array_merge($required, $optional);
        $i = 1;
        
        foreach ($fields as $field) {
            $type = $request['type.' . $field];
            $value = _ax_get_value($type);
            
            $xtpl2->assign('name', htmlspecialchars($type, ENT_QUOTES, 'UTF-8'));
            $xtpl2->assign('id', $i);
            
            if (is_array($value)) {
                $xtpl2->assign('value', htmlspecialchars(implode(',', $value), ENT_QUOTES, 'UTF-8'));
            } elseif ($value != NULL) {
                $xtpl2->assign('value', htmlspecialchars($value, ENT_QUOTES, 'UTF-8'));
            }
            
            $xtpl2->assign('checked', (in_array($field, $required) || !isset($rp['ax_consents']) || in_array($field, $rp['ax_consents'])) ? 'checked="checked"' : '');
            $xtpl2->assign('disabled', (in_array($field, $required)) ? 'disabled="disabled"' : '');
            if (in_array($field, $required)) $xtpl2->parse('fetch_request.ax.required');
            
            $xtpl2->parse('fetch_request.ax');
            
            $i++;
        }

        $xtpl2->assign('ax_data', t('SimpleID will also be sending the following information to the site.'));
        $xtpl2->assign('name_label', t('Type URL'));
        $xtpl2->assign('value_label', t('Value'));
        
        $xtpl2->parse('fetch_request');
        return $xtpl2->text('fetch_request');
    } elseif ($mode == 'store_request') {
        // Sadly, we don't support storage at this stage
        $xtpl2->assign('store_request_message', t('This web site requested to store information about you on SimpleID. Sadly, SimpleID does not support this feature.'));
        $xtpl2->parse('store_request');
        return $xtpl2->text('store_request');
    }
}

/**
 * @see hook_consent()
 */
function ax_consent($form_request, &$response, &$rp) {
    // We only respond if the extension is requested
    if (!openid_extension_requested(OPENID_NS_AX, $response)) return array();
    
    $fields = array_keys(openid_extension_filter_request(OPENID_NS_AX, $response));
    $alias = openid_extension_alias(OPENID_NS_AX);
    
    foreach ($fields as $field) {
        if ((strpos($field, 'value.') !== 0) && (strpos($field, 'count.') !== 0)) continue;
        
        $type_alias = (strpos($field, '.', 6) === FALSE) ? substr($field, 6) : substr($field, strpos($field, '.', 6) - 6);
        $type = $response['openid.' . $alias . '.type.' . $type_alias];
        
        if (isset($response['openid.' . $alias . '.' . $field])) {
            if (!in_array($type, $form_request['ax_consents'])) {
                unset($response['openid.' . $alias . '.' . $field]);
            }
        }
    }
    foreach ($fields as $field) {
        if (strpos($field, 'type.') !== 0) continue;
        $type = $response['openid.' . $alias . '.' . $field];
        
        if (isset($response['openid.' . $alias . '.' . $field])) {
            if (!in_array($type, $form_request['ax_consents'])) {
                unset($response['openid.' . $alias . '.' . $field]);
            }
        }
    }
    
    if (count(array_keys(openid_extension_filter_request(OPENID_NS_AX, $response))) == 0) {
        // We have removed all the responses, so we remove the namespace as well
        unset($response['openid.ns.' . $alias]);
    }
    
    $rp['ax_consents'] = $form_request['ax_consents'];
}

/**
 * @see hook_page_profile()
 */
function ax_page_profile() {
    global $user;
    $xtpl2 = new XTemplate('extensions/ax/ax.xtpl');
    
    if (isset($user['ax'])) {
        foreach ($user['ax'] as $name => $value) {
            $xtpl2->assign('name', htmlspecialchars($name, ENT_QUOTES, 'UTF-8'));
            $xtpl2->assign('value', htmlspecialchars($value, ENT_QUOTES, 'UTF-8'));
            $xtpl2->parse('user_page.ax');
        }
    }
    
    $xtpl2->assign('ax_data', t('SimpleID will send the following information to sites which supports the Attribute Exchange Extension.  If you have also supplied OpenID Connect user information in your identity, or have the Simple Registration Extension installed, these may also be sent as part of this Extension.'));
    $xtpl2->assign('edit_identity_file', t('To change these, <a href="!url">edit your identity file</a>.', array('!url' => 'http://simpleid.koinic.net/docs/1/identity-files/')));
    $xtpl2->assign('name_label', t('Type URL'));
    $xtpl2->assign('value_label', t('Value'));
    
    $xtpl2->parse('user_page');
    
    return array(array(
        'id' => 'ax',
        'title' => t('Attribute Exchange Extension'),
        'content' => $xtpl2->text('user_page')
    ));
}

/**
 * Looks up the value of a specified Attribute Exchange Extension type URI.
 *
 * This function looks up the ax section of the user's identity file.  If the
 * specified type cannot be found, it looks up the corresponding field in the
 * OpenID Connect user information (user_info section) and the Simple Registration
 * Extension (sreg section).
 *
 * @param string $type the type URI to look up
 * @return string the value or NULL if not found
 */
function _ax_get_value($type) {
    global $user;
    global $ax_sreg_map;
    
    if (isset($user['ax'][$type])) {
        return $user['ax'][$type];
    } else {
        // Look up OpenID Connect
        switch ($type) {
            case 'http://axschema.org/namePerson/friendly':
                if (isset($user['user_info']['nickname'])) return $user['user_info']['nickname'];
                break;
            case 'http://axschema.org/contact/email':
                if (isset($user['user_info']['email'])) return $user['user_info']['email'];
                break;
            case 'http://axschema.org/namePerson':
                if (isset($user['user_info']['name'])) return $user['user_info']['name'];
                break;
            case 'http://axschema.org/pref/timezone':
                if (isset($user['user_info']['zoneinfo'])) return $user['user_info']['zoneinfo'];
                break;
            case 'http://axschema.org/person/gender':
                if (isset($user['user_info']['gender'])) return strtoupper(substr($user['user_info']['gender'], 0, 1));
                break;
            case 'http://axschema.org/contact/postalCode/home':
                if (isset($user['user_info']['address']['postal_code'])) return $user['user_info']['address']['postcal_code'];
                break;
        } 
        
        // Look up sreg
        if (isset($ax_sreg_map[$type]) && isset($user['sreg'][$ax_sreg_map[$type]])) {
            return $user['sreg'][$ax_sreg_map[$type]];
        } else {
            return NULL;
        }
    }
}
?>
