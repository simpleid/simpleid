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

use SimpleID\Auth\AuthManager;
use SimpleID\Module;
use SimpleID\Protocols\ProtocolResult;
use SimpleID\Protocols\OpenID\OpenIDCheckEvent;
use SimpleID\Protocols\OpenID\OpenIDModule;
use SimpleID\Protocols\OpenID\Message;
use SimpleID\Protocols\OpenID\Request;
use SimpleID\Protocols\OpenID\OpenIDResponseBuildEvent;
use SimpleID\Store\StoreManager;
use SimpleID\Util\OpaqueIdentifier;
use SimpleID\Util\Events\BaseDataCollectionEvent;

/**
 * Implements the Provider Authentication Policy Extension
 */
class PAPEOpenIDExtensionModule extends Module implements ProtocolResult {

    /** Namespace for the PAPE extension */
    const OPENID_NS_PAPE = 'http://specs.openid.net/extensions/pape/1.0';

    /** Namespaces for PAPE policies */
    const PAPE_POLICY_NONE = 'http://schemas.openid.net/pape/policies/2007/06/none';

    /** Namespaces for PAPE levels */
    const PAPE_LEVEL_NIST800_63 = 'http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf';

    /**
     * Returns the support for PAPE in SimpleID XRDS document
     *
     * @param SimpleID\Util\Event\BaseDataCollectionEvent $event
     */
    public function onXrdsTypes(BaseDataCollectionEvent $event) {
        $event->addResult([
            self::OPENID_NS_PAPE,
            self::PAPE_LEVEL_NIST800_63
        ]);
    }

    /**
     * @see SimpleID\Protocols\OpenID\OpenIDCheckEvent
     */
    public function onOpenIDCheckEvent(OpenIDCheckEvent $event) {
        $request = $event->getRequest();

        // We only respond if the extension is requested
        if (!$request->hasExtension(self::OPENID_NS_PAPE)) return null;
        
        // See if we are choosing an identity and save for later
        // This may be used by pape_response() to produce a private identifier
        if ($request['openid.identity'] == Request::OPENID_IDENTIFIER_SELECT) $this->identifier_select = true;
        
        $pape_request = $request->getParamsForExtension(self::OPENID_NS_PAPE);
        
        // If the relying party provides a max_auth_age
        if (isset($pape_request['max_auth_age'])) {
            $auth = AuthManager::instance();

            // If we are not logged in then we don't need to do anything
            if (!$auth->isLoggedIn()) return NULL;

            $auth_level = $auth->getAuthLevel();
            if ($auth_level == null) $auth_level = AuthManager::AUTH_LEVEL_SESSION;

            $auth_time = $auth->getAuthTime();
            if ($auth_time == null) $auth_time = 0;

            // If the last time we logged on actively (i.e. using a password) is greater than
            // max_auth_age, we then require the user to log in again
            if (($auth_level < AuthLevel::AUTH_LEVEL_CREDENTIALS) 
                || ((time() - $auth->getAuthTime()) > $pape_request['max_auth_age'])) {
                $this->f3->set('message', $this->f3->get('intl.common.reenter_credentials'));
                return self::CHECKID_REENTER_CREDENTIALS;
            }
        }
    }

    /**
     * @see SimpleID\Protocols\OpenID\OpenIDResponseBuildEvent
     */
    public function onOpenIDResponseBuildEvent(OpenIDResponseBuildEvent $event) {
        $auth = AuthManager::instance();
        
        // We only deal with positive assertions
        if (!$event->isPositiveAssertion()) return [];
        
        // We only respond if we are using OpenID 2 or later
        $request = $event->getRequest();
        $response = $event->getResponse();
        
        if ($request->getVersion() < Message::OPENID_VERSION_2) return [];
        
        // Get what is requested
        $pape_request = $request->getParamsForExtension(self::OPENID_NS_PAPE);
            
        // If the extension is requested, we use the same alias, otherwise, we
        // make one up
        $alias = $response->getAliasForExtension(self::OPENID_NS_PAPE, 'pape');
        
        // The PAPE specification recommends us to respond even when the extension
        // is not present in the request.
        $response['ns.' . $alias] = self::OPENID_NS_PAPE;
        
        // We return the last time the user logged in using the login form
        $response[$alias . '.auth_time'] = gmstrftime('%Y-%m-%dT%H:%M:%SZ', $auth->getAuthTime());
        
        // We don't comply with NIST_SP800-63
        $response[$alias . '.auth_level.ns.nist'] = self::PAPE_LEVEL_NIST800_63;
        $response[$alias . '.auth_level.nist'] = 0;
        
        // The default is that we don't apply any authentication policies.
        $response[$alias . '.auth_policies'] = self::PAPE_POLICY_NONE;
    }
}

?>
