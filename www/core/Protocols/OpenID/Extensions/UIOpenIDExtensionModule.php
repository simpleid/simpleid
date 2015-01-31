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

use \Web;
use SimpleID\Auth\AuthManager;
use SimpleID\Module;
use SimpleID\ModuleManager;
use SimpleID\Net\HTTPResponse;
use SimpleID\Protocols\OpenID\Request;
use SimpleID\Protocols\OpenID\Response;
use SimpleID\Util\SecurityToken;

/**
 * Implements the popup and icon modes from the User Interface extension
 *
 * @package simpleid
 * @subpackage extensions
 * @filesource
 */
class UIOpenIDExtensionModule extends Module {
    /** Namespace for the User Interface extension */
    const OPENID_NS_UI = 'http://specs.openid.net/extensions/ui/1.0';

    static function routes($f3) {
        $f3->route('GET /openid/ui/icon/@token', 'SimpleID\Protocols\OpenID\Extensions\UIOpenIDExtensionModule->icon');
    }

    /**
     * Returns the popup mode in SimpleID XRDS document
     *
     * @return array
     * @see hook_xrds_types()
     */
    public function xrdsTypesHook() {
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
    public function openIDResponseHook($assertion, $request, $response) {
        // We only deal with negative assertions
        if ($assertion) return;
        
        // We only respond if the extension is requested
        if (!$request->hasExtension(self::OPENID_NS_UI)) return array();
        
        // We only deal with openid.ui.x-has-session requests
        $filtered_request = $request->getParamsForExtension(self::OPENID_NS_UI);

        if (isset($filtered_request['openid.return_to']) && strstr($filtered_request['openid.return_to'], '#')) {
            $response->setIndirectComponent(Response::OPENID_RESPONSE_FRAGMENT);
        }

        if (!isset($filtered_request['mode']) || ($filtered_request['mode'] != 'x-has-session')) return;
        
        // If user is null, there is no active session
        $auth = AuthManager::instance();
        if (!$auth->isLoggedIn()) return array();
        
        // There is an active session
        $alias = $response->getAliasForExtension(self::OPENID_NS_UI, 'ui');
        
        $response['ns.' . $alias] = self::OPENID_NS_UI;
        $response[$alias . '.mode'] = 'x-has-session';
    }


    /**
     * Detects the presence of the UI extension and modifies the login form
     * accordingly.
     *
     * @param string $destination
     * @param string $state
     * @see hook_user_login_form()
     */
    public function loginFormHook(&$form_state) {
        $destination = $this->f3->get('PARAMS.destination');
        if (!is_string($destination) || (substr($destination, 0, 9) != 'continue/')) return;

        $token = new SecurityToken();
        $payload = $token->getPayload(substr($destination, 9));
        if (($payload === null) || !isset($payload['rq'])) return;

        $request = new Request($payload['rq']);
        
        // Skip if popup does not exist
        if (!$request->hasExtension(self::OPENID_NS_UI)) return;
        
        $filtered_request = $request->getParamsForExtension(self::OPENID_NS_UI);
        if (isset($filtered_request['mode']) && ($filtered_request['mode'] == 'popup')) $this->insertUI();
        
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
    public function openIDConsentFormHook($form_state) {
        $request = $form_state['rq'];

        // Skip if popup does not exist
        if (!$request->hasExtension(self::OPENID_NS_UI)) return;
        
        $filtered_request = $request->getParamsForExtension(self::OPENID_NS_UI);        
        if (isset($filtered_request['mode']) && ($filtered_request['mode'] == 'popup')) $this->insertUI();
        
        if (isset($filtered_request['icon']) && ($filtered_request['icon'] == 'true')) {
            $token = new SecurityToken();

            $realm = $request['openid.realm'];
            $icon_url = $this->build(
                '/openid/ui/icon/@token',
                array('token' => $token->generate($realm, SecurityToken::OPTION_BIND_SESSION))
            );

            return array(
                array(
                    'weight' => -10,
                    'content' = '<div class="icon"><img src="' . $this->f3->clean($icon_url) . '" alt="" /></div>'
                )
            )
        }
    }

    /**
     * Returns an icon.
     */
    public function icon($f3, $params) {
        $token = new SecurityToken();
        $realm = $token->getPayload($params['token'], SIMPLEID_INSTANT_TOKEN_EXPIRES_IN);

        if ($realm === NULL) {
            $this->f3->status(400);
            $this->fatalError($this->t('Invalid UI icon parameters.'));
        }
        
        $icon_res = $this->fetchIcon($realm);
        
        if ($icon_res === NULL) {
            $this->f3->status(404);
            $this->fatalError($this->t('Unable to get icon.'));
        }
        
        header('Via: ' . $icon_res->getVersion() . ' ' . $this->f3->get('HOST'));
        $this->f3->expire(86400);
        header('Content-Type: ' . $icon_res->getHeader('Content-Type'));
        print $icon_res->getBody();
    }

    /**
     * Inserts the necessary CSS and JavaScript code to implement the popup mode
     * from the User Interface extension.
     */
    protected function insertUI() {
        $css = ($this->f3->get('css')) ? $this->f3->get('css') : '';
        $js = ($this->f3->get('javascript')) ? $this->f3->get('javascript') : '';
        
        $this->f3->set('css', $css . '@import url(' . $this->f3->get('base_path') . 'html/openid-ui.css);');
        $this->f3->set('javascript', $js . '<script src="' . $this->f3->get('base_path') . 'html/openid-ui.js" type="text/javascript"></script>');
    }

    /**
     * Attempts to obtain an icon from a RP
     *
     * @param string $realm the openid.realm parameter
     * @return array the response from {@link http_make_request()} with the discovered URL of the
     * RP's icon
     */
    protected function fetchIcon($realm) {
        $mgr = ModuleManager::instance();
        $openid = $mgr->getModule('SimpleID\Protocols\OpenID\OpenIDModule');
        $rp = $openid->loadRelyingParty($realm);
        
        if (isset($rp['ui_icon'])) return $rp['ui_icon'];
        
        $services = $rp->services->getByType('http://specs.openid.net/extensions/ui/icon');
            
        if ($services) {
            $icon_url = $services[0]['uri'];
            
            $web = Web::instance();
            $icon_res = new HTTPResponse($web->request($icon_url));
            if ($icon_res->isHTTPError()) {
                return NULL;
            }
            
            $rp['ui_icon'] = $icon_res;
            $openid->saveRelyingParty($rp);
        } else {
            return NULL;
        }
    }
}

?>
