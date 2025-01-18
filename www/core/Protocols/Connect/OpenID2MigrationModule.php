<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2015-2025
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
use SimpleID\Module;
use SimpleID\ModuleManager;
use SimpleID\Auth\AuthManager;
use SimpleID\Base\RouteContentNegotiationEvent;
use SimpleID\Base\ScopeInfoCollectionEvent;
use SimpleID\Store\StoreManager;

/**
 * Module that implements the OpenID 2 to OpenID Connect migration
 * specification.
 *
 * @link http://openid.net/specs/openid-connect-migration-1_0.html
 */
class OpenID2MigrationModule extends Module {

    public function __construct() {
        parent::__construct();
        
        $mgr = ModuleManager::instance();
        $mgr->loadModule('SimpleID\Protocols\Connect\ConnectModule');
    }

    /**
     * @return void
     */
    public function onRouteContentNegotiationEvent(RouteContentNegotiationEvent $event) {
        if ($event->getRoute() != 'user') return;

        $content_type = $event->negotiate([ 'text/html', 'application/xml', 'application/xhtml+xml', 'application/json' ]);

        if ($content_type == 'application/json') {
            $this->userJSON();
            $event->stopPropagation();
        }
    }

    /**
     * Returns the user's OpenID 2.0 verification page.
     *
     * @return void
     * @see SimpleID\Base\UserModule::user()
     */
    public function userJSON() {
        $mgr = ModuleManager::instance();

        /** @var \SimpleID\Protocols\Connect\ConnectModule $connect_module */
        $connect_module = $mgr->getModule('SimpleID\Protocols\Connect\ConnectModule');
        $iss = $connect_module->getCanonicalHost();
        $store = StoreManager::instance();
        $user = $store->loadUser($this->f3->get('PARAMS.uid'));
        
        if ($user != NULL) {
            header('Content-Type: application/json');
            print json_encode([ 'iss' => $iss ]);
        } else {
            $this->fatalError($this->f3->get('intl.common.user_not_found', $this->f3->get('PARAMS.uid')), 404);
        }
    }

    /**
     * @see SimpleID\Protocols\Connect\ConnectBuildClaimsEvent
     * @return void
     */
    public function onConnectBuildClaimsEvent(ConnectBuildClaimsEvent $event) {
        $context = $event->getContext();
        $scope = $event->getScope();
        $user = $event->getUser();

        if (($context == 'id_token') && in_array('openid2', $scope)) {            
            if (isset($user['openid']['identity'])) {
                $event->addResult([ 'openid2_id' => $user['openid']['identity'] ]);
            }
        }
    }

    /**
     * @see SimpleID\Base\ScopeInfoCollectionEvent
     * @return void
     */
    public function onScopeInfoCollectionEvent(ScopeInfoCollectionEvent $event) {
        $event->addScopeInfo('oauth', [
            'openid2' => [
                'description' => '',
                'weight' => -1
            ]
        ]);
    }
}
?>
