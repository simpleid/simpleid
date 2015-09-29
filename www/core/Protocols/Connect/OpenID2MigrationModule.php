<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2015
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

namespace SimpleID\Protocols\Connect;

use Psr\Log\LogLevel;
use SimpleID\Auth\AuthManager;
use SimpleID\Module;
use SimpleID\ModuleManager;
use SimpleID\Store\StoreManager;

/**
 * Module that implements the OpenID 2 to OpenID Connect migration
 * specification.
 *
 * @link http://openid.net/specs/openid-connect-migration-1_0.html
 */
class OpenID2MigrationModule extends Module {

    static private $scope_settings = NULL;

    public function __construct() {
        parent::__construct();
        
        $mgr = ModuleManager::instance();
        $mgr->loadModule('SimpleID\Protocols\Connect\ConnectModule');
    }

    /**
     * Returns the user's OpenID 2.0 verification page.
     *
     * @see SimpleID\Base\UserModule::user()
     */
    public function userJSON($f3, $params) {
        $mgr = ModuleManager::instance();

        $iss = $mgr->getModule('SimpleID\Protocols\Connect\ConnectModule')->getCanonicalHost();
        $store = StoreManager::instance();
        $user = $store->loadUser($params['uid']);
        
        if ($user != NULL) {
            header('Content-Type: application/json');
            print json_encode(array('iss' => $iss));
        } else {
            $this->f3->status(404);
            
            $this->fatalError($this->t('User %uid not found.', array('%uid' => $uid)));
        }
    }

    /**
     * @see SimpleID\API\ConnectHooks::connectBuildClaimsHook()
     */
    public function connectBuildClaimsHook($user, $client, $context, $scopes, $claims_requested = NULL) {
        if (($context == 'id_token') && in_array('openid2', $scope)) {            
            if (isset($user['openid']['identity'])) {
                return array('openid2_id' => $user['openid']['identity']);
            }
        }
    }

    /**
     * @see SimpleID\API\OAuthHooks::scopesHook()
     */
    public function scopesHook() {
        if (self::$scope_settings == NULL) {
            self::$scope_settings = array(
                'oauth' => array(
                    'openid2' => array(
                        'description' => '',
                        'weight' => -1
                    )
                )
            );
        }
        return self::$scope_settings;
    }
}
?>
