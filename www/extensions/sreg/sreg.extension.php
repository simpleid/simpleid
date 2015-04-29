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
 
/** Namespace for the Simple Registration extension */
define('OPENID_NS_SREG', 'http://openid.net/extensions/sreg/1.1');

/**
 * @see hook_response()
 */
function sreg_response($assertion, $request)
{
    global $user;
    global $version;
    
    // We only deal with positive assertions
    if (!$assertion) {
        return array();
    }
    
    // We only respond if the extension is requested
    if (!openid_extension_requested(OPENID_NS_SREG, $request)) {
        return array();
    }
    
    $request = openid_extension_filter_request(OPENID_NS_SREG, $request);
    $required = (isset($request['required'])) ? explode(',', $request['required']) : array();
    $optional = (isset($request['optional'])) ? explode(',', $request['optional']) : array();
    $fields = array_merge($required, $optional);
    $alias = openid_extension_alias(OPENID_NS_SREG);
    $response = array();
    
    if ($version == OPENID_VERSION_2) {
        $response['openid.ns.' . $alias] = OPENID_NS_SREG;
    }
    
    foreach ($fields as $field) {
        $value = _sreg_get_value($field);
        
        if ($value != null) {
            $response['openid.' . $alias . '.' .  $field] = $value;
        }
    }
    
    return $response;
}

/**
 * Returns an array of fields that need signing.
 *
 * @see hook_signed_fields()
 */
function sreg_signed_fields($response)
{
    // We only respond if the extension is requested
    if (!openid_extension_requested(OPENID_NS_SREG, $response)) {
        return array();
    }
    
    $fields = array_keys(openid_extension_filter_request(OPENID_NS_SREG, $response));
    $alias = openid_extension_alias(OPENID_NS_SREG);
    $signed_fields = array();

    if (isset($response['openid.ns.' . $alias])) {
        $signed_fields[] = 'ns.' . $alias;
    }
    foreach ($fields as $field) {
        if (isset($response['openid.' . $alias . '.' . $field])) {
            $signed_fields[] = $alias . '.' . $field;
        }
    }
    
    return $signed_fields;
}

/**
 * @see hook_consent_form()
 */
function sreg_consent_form($request, $response, $rp)
{
    global $user;
    
    // We only respond if the extension is requested
    if (!openid_extension_requested(OPENID_NS_SREG, $request)) {
        return '';
    }
    
    $request = openid_extension_filter_request(OPENID_NS_SREG, $request);
    $required = (isset($request['required'])) ? explode(',', $request['required']) : array();
    $optional = (isset($request['optional'])) ? explode(',', $request['optional']) : array();
    $fields = array_merge($required, $optional);
    
    if ((count($request)) && isset($user['sreg'])) {
        $xtpl2 = new XTemplate('extensions/sreg/sreg.xtpl');
        
        $xtpl2->assign('alias', openid_extension_alias(OPENID_NS_SREG));
        
        if (isset($request['policy_url'])) {
            $xtpl2->assign('policy', t('You can view the site\'s policy in relation to the use of this information at this URL: <a href="@url">@url</a>.', array('@url' => $request['policy_url'])));
        }
        
        foreach ($fields as $field) {
            $value = _sreg_get_value($field);
        
            if ($value != null) {
                $xtpl2->assign('name', htmlspecialchars($field, ENT_QUOTES, 'UTF-8'));
                $xtpl2->assign('value', htmlspecialchars($value, ENT_QUOTES, 'UTF-8'));
                
                $xtpl2->assign('checked', (in_array($field, $required) || !isset($rp['sreg_consents']) || in_array($field, $rp['sreg_consents'])) ? 'checked="checked"' : '');
                $xtpl2->assign('disabled', (in_array($field, $required)) ? 'disabled="disabled"' : '');
                if (in_array($field, $required)) {
                    $xtpl2->parse('form.sreg.required');
                }
                
                $xtpl2->parse('form.sreg');
            }
        }
        
        $xtpl2->assign('sreg_data', t('SimpleID will also be sending the following registration information to the site.'));
        $xtpl2->assign('name_label', t('Name'));
        $xtpl2->assign('value_label', t('Value'));
        
        $xtpl2->parse('form');
        return $xtpl2->text('form');
    }
}

/**
 * @see hook_consent()
 */
function sreg_consent($form_request, &$response, &$rp)
{
    // We only respond if the extension is requested
    if (!openid_extension_requested(OPENID_NS_SREG, $response)) {
        return;
    }
    
    $fields = array_keys(openid_extension_filter_request(OPENID_NS_SREG, $response));
    $alias = openid_extension_alias(OPENID_NS_SREG);
    
    foreach ($fields as $field) {
        if (isset($response['openid.' . $alias . '.' . $field])) {
            if (!in_array($field, $form_request['sreg_consents'])) {
                unset($response['openid.' . $alias . '.' . $field]);
            }
        }
    }
    
    if (count(array_keys(openid_extension_filter_request(OPENID_NS_SREG, $response))) == 0) {
        // We have removed all the responses, so we remove the namespace as well
        unset($response['openid.ns.' . $alias]);
    }
    
    $rp['sreg_consents'] = $form_request['sreg_consents'];
}

/**
 * @see hook_page_profile()
 */
function sreg_page_profile()
{
    global $user;
    $xtpl2 = new XTemplate('extensions/sreg/sreg.xtpl');
    
    if (isset($user['sreg'])) {
        foreach ($user['sreg'] as $name => $value) {
            $xtpl2->assign('name', htmlspecialchars($name, ENT_QUOTES, 'UTF-8'));
            $xtpl2->assign('value', htmlspecialchars($value, ENT_QUOTES, 'UTF-8'));
            $xtpl2->parse('user_page.sreg');
        }
    }
    
    $xtpl2->assign('sreg_data', t('SimpleID will send the following information to sites which supports the Simple Registration Extension.'));
    $xtpl2->assign('connect_data', t('If you have also supplied OpenID Connect user information in your identity file, these may also be sent as part of this Extension.'));
    $xtpl2->assign('edit_identity_file', t('To change these, <a href="!url">edit your identity file</a>.', array('!url' => 'http://simpleid.koinic.net/documentation/getting-started/setting-identity/identity-files')));
    $xtpl2->assign('name_label', t('Name'));
    $xtpl2->assign('value_label', t('Value'));
    
    $xtpl2->parse('user_page');
    
    return array(array(
        'id' => 'sreg',
        'title' => t('Simple Registration Extension'),
        'content' => $xtpl2->text('user_page')
    ));
}


/**
 * Looks up the value of a specified Simple Registration Extension field.
 *
 * This function looks up the sreg section of the user's identity file.  If the
 * specified field cannot be found, it looks up the corresponding field in the
 * OpenID Connect user information (user_info section).
 *
 * @param string $field the field to look up
 * @return string the value or NULL if not found
 */
function _sreg_get_value($field)
{
    global $user;
    
    if (isset($user['sreg'][$field])) {
        return $user['sreg'][$field];
    } else {
        switch ($field) {
            case 'nickname':
            case 'email':
                if (isset($user['user_info'][$field])) {
                    return $user['user_info'][$field];
                }
                break;
            case 'fullname':
                if (isset($user['user_info']['name'])) {
                    return $user['user_info']['name'];
                }
                break;
            case 'timezone':
                if (isset($user['user_info']['zoneinfo'])) {
                    return $user['user_info']['zoneinfo'];
                }
                break;
            case 'gender':
                if (isset($user['user_info']['gender'])) {
                    return strtoupper(substr($user['user_info']['gender'], 0, 1));
                }
                break;
            case 'postcode':
                if (isset($user['user_info']['address']['postal_code'])) {
                    return $user['user_info']['address']['postcal_code'];
                }
                break;
            default:
                return null;
        }
        return null;
    }
}
