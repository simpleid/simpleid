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
use SimpleID\Protocols\OpenID\Request;
use SimpleID\Protocols\OpenID\Response;

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
     * @see SimpleID\API\OpenIDHooks::openIDResponseHook()
     */
    public function openIDResponseHook($assertion, $request, $response) {
        // We only deal with positive assertions
        if (!$assertion) return;
        
        // We only respond if the extension is requested
        if (!$request->hasExtension(self::OPENID_NS_SREG)) return;

        $user = $this->auth->getUser();
        
        $sreg_request = $request->getParamsForExtension(self::OPENID_NS_SREG);
        $required = (isset($sreg_request['required'])) ? explode(',', $sreg_request['required']) : [];
        $optional = (isset($sreg_request['optional'])) ? explode(',', $sreg_request['optional']) : [];
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
        $request = new Request($form_state->getRequestArray());
        $response = new Response($form_state->getResponseArray());
        $prefs = $form_state['prefs'];
        
        // We only respond if the extension is requested
        if (!$request->hasExtension(self::OPENID_NS_SREG)) return;

        $user = $this->auth->getUser();
        
        $sreg_request = $request->getParamsForExtension(self::OPENID_NS_SREG);
        $required = (isset($sreg_request['required'])) ? explode(',', $sreg_request['required']) : [];
        $optional = (isset($sreg_request['optional'])) ? explode(',', $sreg_request['optional']) : [];
        $fields = array_merge($required, $optional);

        // Check we have any response to consent to
        if (!count($response->getParamsForExtension(self::OPENID_NS_SREG))) return;
        
        $tpl = new \Template();
        $hive = [
            'module' => 'sreg',
            'userinfo_label' => $this->f3->get('intl.common.consent.send_label'),
            'name_label' => $this->f3->get('intl.common.name'),
            'value_label' => $this->f3->get('intl.common.value'),
            'fields' => []
        ];
            
        if (isset($sreg_request['policy_url'])) {
            $hive['policy_url'] = $sreg_request['policy_url'];
        }
            
        foreach ($fields as $field) {
            $value = $this->getValue($user, $field);
        
            if ($value != NULL) {
                $form_field = [
                    'id' => $field,
                    'html_id' => $field,
                    'name' => $field,
                    'value' => $value,
                ];

                if (in_array($field, $required)) {
                    $form_field['required'] = true;
                } else {
                    $form_field['required'] = false;
                    $form_field['checked'] = (!isset($prefs['consents']['sreg']) || in_array($field, $prefs['consents']['sreg']));
                }
                
                $hive['fields'][] = $form_field;
            }
        }
            
        return [
            [
                'content' => $tpl->render('openid_userinfo_consent.html', false, $hive),
                'weight' => 0
            ]
        ];
        
    }

    /**
     * @see hook_consent()
     */
    function openIDConsentFormSubmitHook($form_state) {
        $response = new Response($form_state->getResponseArray());
        $prefs =& $form_state->pathRef('prefs');

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
        $form_state->setResponse($response);
    }

    /**
     * @see hook_page_profile()
     */
    public function profileBlocksHook() {
        $user = $this->auth->getUser();

        if (!isset($user['sreg'])) return;

        $tpl = new \Template();
        $hive = [
            'userinfo_label' => $this->f3->get('intl.core.openid.sreg.profile_block'),
            'name_label' => $this->f3->get('intl.common.name'),
            'value_label' => $this->f3->get('intl.common.value'),
            'info' => $user['sreg']
        ];
        
        return [ [
            'id' => 'sreg',
            'title' => $this->f3->get('intl.core.openid.sreg.sreg_title'),
            'content' => $tpl->render('openid_userinfo_profile.html', false, $hive),
        ] ];
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
        $sreg = (isset($user['sreg'])) ? $user['sreg'] : [];
        $userinfo = (isset($user['userinfo'])) ? $user['userinfo'] : [];
        
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
