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
use SimpleID\Protocols\OpenID\OpenIDModule;
use SimpleID\Protocols\OpenID\Message;
use SimpleID\Protocols\OpenID\Request;
use SimpleID\Store\StoreManager;
use SimpleID\Util\OpaqueIdentifier;

/**
 * Implements the Provider Authentication Policy Extension
 */
class PAPEOpenIDExtensionModule extends Module {

    /** Namespace for the PAPE extension */
    const OPENID_NS_PAPE = 'http://specs.openid.net/extensions/pape/1.0';

    /** Namespaces for PAPE policies */
    const PAPE_POLICY_NONE = 'http://schemas.openid.net/pape/policies/2007/06/none';
    const PAPE_POLICY_PPID = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier';

    /** Namespaces for PAPE levels */
    const PAPE_LEVEL_NIST800_63 = 'http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf';

    /** @var bool true if there is no identifier in the current authentication request */
    private $identifier_select = false;

    static function routes($f3) {
        $f3->route('GET /openid/ppid/@ppid', 'SimpleID\Protocols\OpenID\Extensions\PAPEOpenIDExtensionModule->ppidPage');
    }

    /**
     * Returns the support for PAPE in SimpleID XRDS document
     *
     * @return array
     * @see hook_xrds_types()
     */
    public function xrdsTypesHook() {
        return array(
            self::OPENID_NS_PAPE,
            self::PAPE_POLICY_PPID,
            self::PAPE_LEVEL_NIST800_63
        );
    }

    /**
     * @see hook_checkid_identity()
     */
    public function openIDCheckIdentityHook($request, $identity, $immediate) {
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
            if (($auth_level <= AuthLevel::AUTH_LEVEL_CREDENTIALS) 
                || ((time() - $auth->getAuthTime()) > $pape_request['max_auth_age'])) {
                $this->f3->set('message', $this->t('This web site\'s policy requires you to log in again to confirm your identity.'));
                return OpenIDModule::CHECKID_REENTER_CREDENTIALS;
            }
        }
    }

    /**
     * @see hook_response()
     */
    function openIDResponseHook($assertion, $request, $response) {
        $auth = AuthManager::instance();
        
        // We only deal with positive assertions
        if (!$assertion) return array();
        
        // We only respond if we are using OpenID 2 or later
        if ($request->getVersion() < Message::OPENID_VERSION_2) return array();
        
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
        
        // The default is that we don't apply any authentication policies. This can be changed later in the
        // function
        $response[$alias . '.auth_policies'] = self::PAPE_POLICY_NONE;

        // Now we go through the authentication policies
        if (isset($pape_request['preferred_auth_policies'])) {
            $policies = preg_split('/\s+/', $pape_request['preferred_auth_policies']);
            
            if (in_array(self::PAPE_POLICY_PPID, $policies)) {
                // We want a ppid.  Check that the authentication request is correct
                if ($this->identifier_select) {
                    $realm = $request->getRealm();
                    $identity = $request['openid.identity'];
                    
                    $ppid = $this->generatePPID($identity, $realm);
                    $response['claimed_id'] = $ppid;
                    $response['identity'] = $ppid;
                }
            }
        }
    }

    /**
     * Generates a private personal identifier (PPID).  The PPID is an opaque identifier
     * for a particular user-RP pair
     *
     * @param string $identity the identity of the user
     * @param string $realm the URL of the relying party
     * @return string the PPID
     */
    function generatePPID($identity, $realm) {
        $opaque = new OpaqueIdentifier();
        
        $parts = parse_url($realm);
        $host = $parts['host'];
        if (strstr($host, 'www.') === 0) $host = substr($host, 4);
        
        return $this->getCanonicalURL('openid/ppid/' . $opaque->generate($identity, array('aud' => $host)));
    }

    /**
     * Returns the public page for a private personal ID.
     *
     * @param string $ppid the PPID
     */
    function ppidPage($f3, $params) {
        $web = \Web::instance();

        $ppid = $params['ppid'];
        
        header('Vary: Accept');
                
        $content_type = $web->acceptable(array('text/html', 'application/xml', 'application/xhtml+xml', 'application/xrds+xml'));
                
        if (($content_type == 'application/xrds+xml') || ($this->f3->get('GET.format') == 'xrds')) {
            header('Content-Type: application/xrds+xml');
            header('Content-Disposition: inline; filename=yadis.xml');
        
            $tpl = new \Template();
            print $tpl->render('openid_user_xrds.xml', 'application/xrds+xml');
            return;
        } else {
            header('X-XRDS-Location: ' . $this->getCanonicalURL('openid/ppid/' . rawurlencode($ppid), 'format=xrds'));
                    
            $this->f3->set('title', $this->t('Private Personal Identifier'));
            $this->f3->set('message', $this->t('This is a private personal identifier.'));
            $tpl = new \Template();
            print $tpl->render('page.html');
        }   
    }
}

?>
