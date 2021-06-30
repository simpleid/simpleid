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

namespace SimpleID\Base;

use Psr\Log\LogLevel;
use SimpleID\Module;
use SimpleID\ModuleManager;
use SimpleID\Auth\AuthManager;
use SimpleID\Store\StoreManager;
use SimpleID\Util\SecurityToken;


class UserModule extends Module {
    static function init($f3) {
        $f3->route('GET /user/@uid', 'SimpleID\Base\UserModule->user');
    }

    /**
     * Returns the user's public page.
     * 
     * @param string $uid the user ID
     */
    function user($f3, $params) {
        $web = \Web::instance();
        $tpl = \Template::instance();
        $store = StoreManager::instance();
        $mgr = ModuleManager::instance();
        
        $this->f3->set('title', $this->f3->get('intl.core.user.user_title'));
        if (!isset($params['uid'])) {
            $this->f3->status(400);
            $this->f3->set('message', $this->f3->get('intl.common.missing_uid'));
        } else {
            $user = $store->loadUser($params['uid']);
            
            if ($user == NULL) {
                $this->f3->status(404);
                $this->f3->set('message', $this->f3->get('intl.common.user_not_found', $params['uid']));
            } else {
                header('Vary: Accept');
                
                $content_type = $web->acceptable([ 'text/html', 'application/xml', 'application/xhtml+xml', 'application/xrds+xml', 'application/json' ]);
                
                if (($content_type == 'application/xrds+xml') && ($mgr->isModuleLoaded('SimpleID\Protocols\OpenID\OpenIDModule'))) {
                    $mgr->getModule('SimpleID\Protocols\OpenID\OpenIDModule')->userXRDS($f3, $params);
                    return;
                } elseif (($content_type == 'application/json') && ($mgr->isModuleLoaded('SimpleID\Protocols\Connect\OpenID2MigrationModule'))) {
                    $mgr->getModule('SimpleID\Protocols\Connect\OpenID2MigrationModule')->userJSON($f3, $params);
                } else {
                    $xrds_location = $this->getCanonicalURL('@openid_user_xrds');
                    header('X-XRDS-Location: ' . $xrds_location);
                    
                    $this->f3->set('message', $this->f3->get('intl.core.user.user_page', $params['uid']));
                    
                    $this->f3->set('title', $user['uid']);
                    $this->f3->set('xrds', $xrds_location);
                    if ($user->hasLocalOpenIDIdentity()) {
                        $this->f3->set('local_id', $user["identity"]);
                    }

                    $this->f3->set('head', 'openid_head.html');
                }
            }
        }
        
        print $tpl->render('page.html');
    }

    /**
     * Returns a block containing OpenID Connect user information.
     *
     * @return array the OpenID Connect user information block
     */
    function profileBlocksHook() {
        $auth = AuthManager:: instance();
        $user = $auth->getUser();
        
        $html = '<p>' . $this->f3->get('intl.core.user.profile_label') . '</p>';    
        
        $html .= "<table><tr><th>" . $this->f3->get('intl.common.name') . "</th><th>" . $this->f3->get('intl.common.value') . "</th></tr>";
        
        if (isset($user['userinfo'])) {
            foreach ($user['userinfo'] as $member => $value) {
                if (is_array($value)) {
                    foreach ($value as $submember => $subvalue) {
                        $html .= "<tr><td>" . $this->f3->clean($member) . " (" .$this->f3->clean($submember) . ")</td><td>" . $this->f3->clean($subvalue) . "</td></tr>";
                    }
                } else {
                    $html .= "<tr><td>" . $this->f3->clean($member) . "</td><td>" . $this->f3->clean($value) . "</td></tr>";
                }
            }
        }
        
        $html .= "</table>";
        
        return [ [
            'id' => 'userinfo',
            'title' => $this->f3->get('intl.core.user.userinfo_title'),
            'content' => $html,
            'weight' => -1
        ] ];
    }
}

?>
