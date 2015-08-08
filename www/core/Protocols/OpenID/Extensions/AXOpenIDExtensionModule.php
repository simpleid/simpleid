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
 * 
 */

namespace SimpleID\Protocols\OpenID\Extensions;

use SimpleID\Module;
use SimpleID\Auth\AuthManager;

/**
 * Implements the Attribute Exchange extension.
 * 
 *
 * @package simpleid
 * @subpackage extensions
 * @filesource
 */
class AXOpenIDExtensionModule extends Module {
    /** Namespace for the Simple Registration extension */
    const OPENID_NS_AX = 'http://openid.net/srv/ax/1.0';

    private $auth;

    public function __construct() {
        parent::__construct();
        $this->auth = AuthManager::instance();
    }

    /**
     * Returns the support for AX in SimpleID XRDS document
     *
     * @return array
     * @see hook_xrds_types()
     */
    function xrdsTypesHook() {
        return array(self::OPENID_NS_AX);
    }

    /**
     * @see hook_response()
     */
    public function openIDResponseHook($assertion, $request, $response) {
        // We only deal with positive assertions
        if (!$assertion) return;
        
        // We only respond if the extension is requested
        if (!$request->hasExtension(self::OPENID_NS_AX)) return;
        
        $user = $this->auth->getUser();
        
        $ax_request = $request->getParamsForExtension(self::OPENID_NS_AX);
        if (!isset($ax_request['mode'])) return;
        $mode = $ax_request['mode'];
        
        $alias = $response->getAliasForExtension(self::OPENID_NS_AX, 'ax');        
        $response['ns.' . $alias] = self::OPENID_NS_AX;
        
        if ($mode == 'fetch_request') {
            $response[$alias . '.mode'] = 'fetch_response';
            
            $required = (isset($ax_request['required'])) ? explode(',', $ax_request['required']) : array();
            $optional = (isset($ax_request['if_available'])) ? explode(',', $ax_request['if_available']) : array();
            $fields = array_merge($required, $optional);
            
            foreach ($fields as $field) {
                if (!isset($ax_request['type.' . $field])) continue;
                $type = $ax_request['type.' . $field];
                $response[$alias . '.type.' . $field] = $type;
                $value = $this->getValue($user, $type);
                
                if ($value == NULL) {
                    $response[$alias . '.count.' .  $field] = 0;
                } elseif (is_array($value)) {
                    $response[$alias . '.count.' .  $field] = count($value);
                    for ($i = 0; $i < count($value); $i++) {
                        $response[$alias . '.value.' .  $field . '.' . ($i + 1)] = $value[$i];
                    }
                } else {
                    $response[$alias . '.value.' .  $field] = $value;
                }
            }
        } elseif ($mode == 'store_request') {
            // Sadly, we don't support storage at this stage
            $response[$alias . '.mode'] = 'store_response_failure';
            $response[$alias . '.error'] = 'OpenID provider does not support storage of attributes';
        }
        
        return;
    }

    /**
     * @see hook_consent_form()
     */
    public function openIDConsentFormHook($form_state) {
        $request = $form_state['rq'];
        $response = $form_state['rs'];
        $prefs = $form_state['prefs'];
        
        // We only respond if the extension is requested
        if (!$request->hasExtension(self::OPENID_NS_AX)) return;

        $user = $this->auth->getUser();
        
        $ax_request = $request->getParamsForExtension(self::OPENID_NS_AX);
        if (!isset($ax_request['mode'])) return;
        $mode = $ax_request['mode'];
        
        if ($mode == 'fetch_request') {
            $tpl = new \Template();
            $hive = array(
                'module' => 'ax',
                'userinfo_label' => $this->t('SimpleID will also be sending the following information to the site.'),
                'name_label' => $this->t('Type URL'),
                'value_label' => $this->t('Value'),
                'fields' => array()
            );

            $required = (isset($ax_request['required'])) ? explode(',', $ax_request['required']) : array();
            $optional = (isset($ax_request['if_available'])) ? explode(',', $ax_request['if_available']) : array();
            $fields = array_merge($required, $optional);
            $i = 1;
            
            foreach ($fields as $field) {
                if (!isset($ax_request['type.' . $field])) continue;
                $type = $ax_request['type.' . $field];
                $value = $this->getValue($user, $type);
                if ($value == NULL) continue;
                if (is_array($value)) $value = implode(',', $value);

                $form_field = array(
                    'id' => $type,
                    'html_id' => $i,
                    'name' => $type,
                    'value' => $value,
                );

                if (in_array($field, $required)) {
                    $form_field['required'] = true;
                } else {
                    $form_field['required'] = false;
                    $form_field['checked'] = (!isset($prefs['consents']['ax']) || in_array($field, $prefs['consents']['ax'])) ;
                }
                
                $hive['fields'][] = $form_field;
                $i++;
            }

            return array(
                array(
                    'content' => $tpl->render('openid_userinfo_consent.html', false, $hive),
                    'weight' => 0
                )
            );
        } elseif ($mode == 'store_request') {
            // Sadly, we don't support storage at this stage
            $this->f3->set('message', $this->t('This web site requested to store information about you on SimpleID. Sadly, SimpleID does not support this feature.'));
        }
    }

    /**
     * @see hook_consent()
     */
    function openIDConsentFormSubmitHook(&$form_state) {
        $request = &$form_state['rq'];
        $response = &$form_state['rs'];
        $prefs = &$form_state['prefs'];

        // We only respond if the extension is requested
        if (!$response->hasExtension(self::OPENID_NS_AX)) return;
        
        $fields = array_keys($response->getParamsForExtension(self::OPENID_NS_AX));
        $alias = $response->getAliasForExtension(self::OPENID_NS_AX, 'ax');
        $form = $this->f3->get('POST.prefs.consents.ax');
        
        foreach ($fields as $field) {
            if ((strpos($field, 'value.') !== 0) && (strpos($field, 'count.') !== 0)) continue;
            
            $type_alias = (strpos($field, '.', 6) === FALSE) ? substr($field, 6) : substr($field, strpos($field, '.', 6) - 6);
            $type = $response[$alias . '.type.' . $type_alias];
            
            if (isset($response[$alias . '.' . $field])) {
                if (!in_array($type, $form)) {
                    unset($response[$alias . '.' . $field]);
                }
            }
        }
        foreach ($fields as $field) {
            if (strpos($field, 'type.') !== 0) continue;
            $type = $response[$alias . '.' . $field];
            
            if (isset($response[$alias . '.' . $field])) {
                if (!in_array($type, $form)) {
                    unset($response[$alias . '.' . $field]);
                }
            }
        }
        
        if (count(array_keys($response->getParamsForExtension(self::OPENID_NS_AX))) == 0) {
            // We have removed all the responses, so we remove the namespace as well
            unset($response['ns.' . $alias]);
        }
        
        $prefs['consents']['sreg'] = $form;
    }

    /**
     * @see hook_page_profile()
     */
    public function profileBlocksHook() {
        $user = $this->auth->getUser();

        if (!isset($user['ax'])) return;

        $tpl = new \Template();
        $hive = array(
            'userinfo_label' => $this->t('SimpleID may send the following additional information to sites which supports the Attribute Exchange Extension.'),
            'name_label' => $this->t('Type URL'),
            'value_label' => $this->t('Value'),
            'info' => $user['ax']
        );
        
        return array(array(
            'id' => 'ax',
            'title' => t('Attribute Exchange Extension'),
            'content' => $tpl->render('openid_userinfo_profile.html', false, $hive),
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
    protected function getValue($user, $type) {
        $ax = (isset($user['ax'])) ? $user['ax'] : array();
        $sreg = (isset($user['sreg'])) ? $user['sreg'] : array();
        $userinfo = (isset($user['userinfo'])) ? $user['userinfo'] : array();
        
        if (isset($ax[$type])) {
            return $ax[$type];
        } else {
            // Look up OpenID Connect
            switch ($type) {
                case 'http://axschema.org/namePerson/friendly':
                    if (isset($userinfo['nickname'])) return $userinfo['nickname'];
                    break;
                case 'http://axschema.org/contact/email':
                    if (isset($userinfo['email'])) return $userinfo['email'];
                    break;
                case 'http://axschema.org/namePerson':
                    if (isset($userinfo['name'])) return $userinfo['name'];
                    break;
                case 'http://axschema.org/pref/timezone':
                    if (isset($userinfo['zoneinfo'])) return $userinfo['zoneinfo'];
                    break;
                case 'http://axschema.org/person/gender':
                    if (isset($userinfo['gender'])) return strtoupper(substr($userinfo['gender'], 0, 1));
                    break;
                case 'http://axschema.org/contact/postalCode/home':
                    if (isset($userinfo['address']['postal_code'])) return $userinfo['address']['postcal_code'];
                    break;
            }
        }
    }
}

?>
