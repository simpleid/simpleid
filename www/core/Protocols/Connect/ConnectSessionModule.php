<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2016
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
use SimpleID\Crypt\Random;
use SimpleID\Protocols\OAuth\Response;
use SimpleID\Util\SecurityToken;
use SimpleID\Module;
use SimpleJWT\JWT;

class ConnectSessionModule extends Module {
    static function routes($f3) {
        $f3->route('GET @connect_check_session: /connect/session', 'SimpleID\Protocols\Connect\ConnectSessionModule->check_session');
        $f3->route('GET @connect_logout: /connect/logout', 'SimpleID\Protocols\Connect\ConnectSessionModule->logout');
        $f3->route('GET /connect/logout/@token', 'SimpleID\Protocols\Connect\ConnectSessionModule->logout');
    }

    /**
     * Provides a page for use in an iframe to determine whether session status
     * has changed
     *
     */
    public function check_session() {
        $auth = AuthManager::instance();
        $tpl = new \Template();

        $this->f3->set('cookie_name', $auth->getCookieName('uals'));
        
        print $tpl->render('connect_check_session.html');
    }

    /**
     * Logout endpoint
     */
    public function logout($f3, $params) {
        $token = new SecurityToken();

        if (isset($params['token'])) {
            // All done, redirect to post_logout_redirect_uri
            $payload = $token->getPayload($params['token']);

            if ($payload === null) {
                $this->f3->fatalError($this->t('Invalid request.'));
                return;
            }

            $response = new Response();
            if (isset($payload['s'])) $response['state'] = $payload['s'];
            $response->renderRedirect($payload['r']);
        } else {
            // if id_token_hint AND current user, then do not prompt, otherwise, do
            if ($this->f3->exists('REQUEST.id_token_hint')) {
                try {
                    $jwt = JWT::decode($request['id_token_hint']);
                    $user_match = ($jwt->getClaim('sub') == $this->getSubject($auth->getUser(), $client));
                } catch (CryptException $e) {
                    $user_match = false;
                }/*
                if (!$user_match) {
                    $auth->logout();
                    return OAuthModule::LOGIN_REQUIRED;
                }*/
            }
            // Save state [post_logout_redirect_uri, state], set destination and prompts
            $form_state = array(
                'r' => $this->f3->get('REQUEST.post_logout_redirect_uri'),
                's' => $this->f3->get('REQUEST.state')
            );

            // logout form
            
            $this->f3->set('destination', '/connect/logout/' . $token->generate($form_state));  // CHECK this
            $this->f3->reroute('@auth_logout');
        }
    }

    /**
     * Builds the OpenID Connect Session Management response on a successful
     * authentication.
     * 
     * @see SimpleID\API\OAuthHooks::oAuthGrantAuthHook()
     */
    public function oAuthGrantAuthHook($authorization, $request, $response, $scopes) {
        $response['session_state'] = $this->buildSessionState($request['client_id'], $request['redirect_uri']);
    }

    /**
     * @see SimpleID\API\ConnectHooks::connectConfigurationHook()
     */
    public function connectConfigurationHook() {
        return array(
            'check_session_iframe' => $this->getCanonicalURL('@connect_check_session', '', 'https'),
            'end_session_endpoint' => $this->getCanonicalURL('@connect_logout', 'https')
        );
    }

    /**
     * Builds a session state.  The session state is bound to:
     *
     * - the client ID
     * - the origin of the redirect URI
     * - the user agent login state {@link \SimpleID\Auth\AuthManager::assignUALoginState()}
     *
     * @param string $client_id the client ID
     * @param string $redirect_uri the redirect URI
     * @return string the session state
     * @link https://openid.net/specs/openid-connect-session-1_0.html#CreatingUpdatingSessions
     */
    private function buildSessionState($client_id, $redirect_uri) {
        $auth = AuthManager::instance();
        $rand = new Random();

        $origin = $this->getOrigin($redirect_uri);

        $uals = $auth->assignUALoginState();
        $salt = $rand->secret(8);
        return hash_hmac('sha256', $client_id . ' ' . $origin . ' ' . $salt, $uals) . '.' . $salt;
    }

    /**
     * Gets the origin of a URI
     *
     * @param string $uri the URI
     * @return string the origin
     * @link https://www.rfc-editor.org/rfc/rfc6454.txt
     */
    private function getOrigin($uri) {
        $parts = parse_url($uri);
        
        $origin = $parts['scheme'] . '://';
        $origin .= $parts['host'];
        if (isset($parts['port'])) $origin .= ':' . $parts['port'];
        
        return $origin;
    }
}



?>
