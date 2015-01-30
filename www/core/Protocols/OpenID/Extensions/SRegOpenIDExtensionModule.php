<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014
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
 */

namespace SimpleID\Protocols\OpenID\Extensions;

use SimpleID\Module;
use SimpleID\Auth\AuthManager;
use SimpleID\Protocols\OpenID\Message;

/**
 * Implements the Simple Registration extension.
 * 
 *
 * @package simpleid
 * @subpackage extensions
 * @filesource
 */
class SRegOpenIDExtensionModule extends Module {
    /** Namespace for the Simple Registration extension */
    const OPENID_NS_SREG = 'http://openid.net/extensions/sreg/1.1';

    private $auth;

    public function __construct() {
        parent::__construct();
        $this->auth = AuthManager::instance();
    }

    /**
     * @see hook_response()
     */
    public function openIDResponseHook($assertion, $request, $response) {
        // We only deal with positive assertions
        if (!$assertion) return;
        
        // We only respond if the extension is requested
        if (!$request->hasExtension(self::OPENID_NS_SREG)) return;

        $user = $this->auth->getUser();
        
        $sreg_request = $request->getParamsForExtension(self::OPENID_NS_SREG);
        $required = (isset($sreg_request['required'])) ? explode(',', $sreg_request['required']) : array();
        $optional = (isset($sreg_request['optional'])) ? explode(',', $sreg_request['optional']) : array();
        $fields = array_merge($required, $optional);

        $alias = $response->getAliasForExtension(self::OPENID_NS_SREG, 'sreg');
        
        if ($request->getVersion() == Message::OPENID_VERSION_2) $response['ns.' . $alias] = self::OPENID_NS_SREG;
        
        foreach ($fields as $field) {
            $value = $this->getValue($user, $field);
            if ($value != NULL) $response[$alias . '.' .  $field] = $value;
        }
    }

    /**
     * @see hook_consent_form()
     */
    function openIDConsentFormHook($form_state) {
        $request = $form_state['rq'];
        $response = $form_state['rs'];
        $prefs = $form_state['prefs'];
        
        // We only respond if the extension is requested
        if (!$request->hasExtension(self::OPENID_NS_SREG)) return;

        $user = $this->auth->getUser();
        
        $sreg_request = $request->getParamsForExtension(self::OPENID_NS_SREG);
        $required = (isset($sreg_request['required'])) ? explode(',', $sreg_request['required']) : array();
        $optional = (isset($sreg_request['optional'])) ? explode(',', $sreg_request['optional']) : array();
        $fields = array_merge($required, $optional);

        // Check we have any response to consent to
        if (!count($response->getParamsForExtension(self::OPENID_NS_SREG))) return;
        
        $tpl = new \Template();
        $hive = array(
            'module' => 'sreg',
            'userinfo_label' => $this->t('SimpleID will also be sending the following information to the site.'),
            'name_label' => $this->t('Name'),
            'value_label' => $this->t('Value'),
            'fields' => array()
        );
            
        if (isset($request['policy_url'])) {
            $hive['policy_label'] = $this->t('You can view the site\'s policy in relation to the use of this information at this URL: <a href="@url">@url</a>.', array('@url' => $request['policy_url']));
        }
            
        foreach ($fields as $field) {
            $value = $this->getValue($user, $field);
        
            if ($value != NULL) {
                $form_field = array(
                    'id' => $field,
                    'html_id' => $field,
                    'name' => $field,
                    'value' => $value,
                );

                if (in_array($field, $required)) {
                    $form_field['required'] = true;
                } else {
                    $form_field['required'] = false;
                    $form_field['checked'] = (!isset($prefs['consents']['sreg']) || in_array($field, $prefs['consents']['sreg'])) ;
                }
                
                $hive['fields'][] = $form_field;
            }
        }
            
        return array(
            array(
                'content' => $tpl->render('openid_userinfo_consent.html', false, $hive),
                'weight' => 0
            )
        );
        
    }

    /**
     * @see hook_consent()
     */
    function openIDConsentFormSubmitHook(&$form_state) {
        $request = &$form_state['rq'];
        $response = &$form_state['rs'];
        $prefs = &$form_state['prefs'];

        // We only respond if the extension is requested
        if (!$response->hasExtension(self::OPENID_NS_SREG)) return;
        
        $fields = array_keys($response->getParamsForExtension(self::OPENID_NS_SREG));
        $alias = $response->getAliasForExtension(self::OPENID_NS_SREG, 'sreg');
        $form = $this->f3->get('POST.prefs.consents.sreg');

        foreach ($fields as $field) {
            if (isset($response[$alias . '.' . $field])) {
                if (!in_array($field, $form)) {
                    unset($response[$alias . '.' . $field]);
                }
            }
        }
        
        if (count(array_keys($response->getParamsForExtension(self::OPENID_NS_SREG))) == 0) {
            // We have removed all the responses, so we remove the namespace as well
            unset($response['ns.' . $alias]);
        }
        
        $prefs['consents']['sreg'] = $form;
    }

    /**
     * @see hook_page_profile()
     */
    public function profileBlocksHook() {
        $user = $auth->getUser();

        if (!isset($user['sreg'])) return;

        $tpl = new \Template();
        $hive = array(
            'userinfo_label' => $this->t('SimpleID may send the following additional information to sites which supports the Simple Registration Extension.'),
            'name_label' => $this->t('Name'),
            'value_label' => $this->t('Value'),
            'info' => $user['sreg']
        );
        
        return array(array(
            'id' => 'sreg',
            'title' => t('Simple Registration Extension'),
            'content' => $tpl->render('openid_userinfo_profile.html', false, $hive),
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
    protected function getValue($user, $field) {
        $sreg = (isset($user['sreg'])) ? $user['sreg'] : array();
        $userinfo = (isset($user['userinfo'])) ? $user['userinfo'] : array();
        
        if (isset($sreg[$field])) {
            return $sreg[$field];
        } else {
            switch ($field) {
                case 'nickname':
                case 'email':
                    if (isset($userinfo[$field])) return $userinfo[$field];
                    break;
                case 'fullname':
                    if (isset($userinfo['name'])) return $userinfo['name'];
                    break;
                case 'timezone':
                    if (isset($userinfo['zoneinfo'])) return $userinfo['zoneinfo'];
                    break;
                case 'gender':
                    if (isset($userinfo['gender'])) return strtoupper(substr($userinfo['gender'], 0, 1));
                    break;
                case 'postcode':
                    if (isset($userinfo['address']['postal_code'])) return $userinfo['address']['postcal_code'];
                    break;
                default:
                    return NULL;
            } 
            return NULL;
        }
    }
}

?>
