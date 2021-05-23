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
use SimpleID\Protocols\Connect\ConnectModule;
use SimpleID\Protocols\OAuth\Response;
use SimpleID\Store\StoreManager;
use SimpleID\Util\SecurityToken;
use SimpleID\Module;
use SimpleJWT\InvalidTokenException;

class ConnectSessionModule extends Module {
    static function routes($f3) {
        $f3->route('GET @connect_check_session: /connect/session', 'SimpleID\Protocols\Connect\ConnectSessionModule->check_session');
        $f3->route('GET|POST @connect_logout: /connect/logout', 'SimpleID\Protocols\Connect\ConnectSessionModule->logout');
        $f3->route('GET @connect_logout_complete: /connect/logout_complete/@token', 'SimpleID\Protocols\Connect\ConnectSessionModule->logoutComplete');
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
     * Relying party-initiated logout endpoint
     */
    public function logout($f3, $params) {
        $store = StoreManager::instance();
        $auth = AuthManager::instance();

        if ($this->f3->exists('POST.fs') !== false) {            
            $token = new SecurityToken();
            $form_state = $token->getPayload($this->f3->get('POST.fs'));

            if (!$token->verify($this->f3->get('POST.tk'), 'connect_logout')) {
                $this->logger->log(LogLevel::WARNING, 'Security token ' . $this->f3->get('POST.tk') . ' invalid.');
                $this->f3->set('message', $this->f3->get('intl.common.invalid_tk'));
                $this->logoutForm($form_state);
                return;
            }

            if ($this->f3->get('POST.op') == $this->f3->get('intl.common.cancel')) {
                if ($form_state['connect_logout']['post_logout_redirect_uri']) {
                    $response = new Response();
                    if (isset($form_state['connect_logout']['state'])) $response['state'] = $form_state['connect_logout']['state'];
                    $response->renderRedirect($form_state['connect_logout']['post_logout_redirect_uri']);
                } else {
                    $this->f3->set('message', $this->f3->get('intl.common.logout_cancelled'));

                    $index_module = $this->mgr->getModule('SimpleID\Base\IndexModule');
                    $index_module->index();                    
                }
                return;
            } else {
                if ($form_state['connect_logout']['post_logout_redirect_uri']) {
                    // set up continue param and redirect
                    $state = [ 'rt' => 'connect/logout_complete/' . $token->generate($form_state['connect_logout']) ];

                    $destination = 'continue/' . rawurlencode($token->generate($state));
                    $this->f3->reroute('@auth_logout(1=' . $destination . ')');
                } else {
                    $this->f3->reroute('@auth_logout');
                }
            }
        } else {
            $form_state = [ 'connect_logout' => [] ];
            if ($this->f3->exists('REQUEST.state')) $form_state['connect_logout']['state'] = $this->f3->get('REQUEST.state');

            // Check for id_token_hint.  If it is a valid ID token AND it is the
            // current logged in user, then we can proceed with log out.  Otherwise
            // we ignore the logout request
            if ($this->f3->exists('REQUEST.id_token_hint')) {
                try {
                    $id_token_hint = $this->f3->get('REQUEST.id_token_hint');
                    $jwt = JWT::deserialise($id_token_hint);
                    $claims = $jwt['claims'];

                    $client_id = $claims['aud'];
                    $sub = $claims['sub'];

                    $client = $store->loadClient($client_id, 'SimpleID\Protocols\OAuth\OAuthClient');

                    $user_match = $client && ($sub == ConnectModule::getSubject($auth->getUser(), $client));

                    if ($client && $client['connect']['post_logout_redirect_uris'] && $this->f3->exists('REQUEST.post_logout_redirect_uri')) {
                        $post_logout_redirect_uri = $this->f3->get('REQUEST.post_logout_redirect_uri');

                        if (in_array($post_logout_redirect_uri, $client['connect']['post_logout_redirect_uris']))
                            $form_state['connect_logout']['post_logout_redirect_uri'] = $post_logout_redirect_uri;
                    }
                } catch (InvalidTokenException $e) {
                    $user_match = false;
                }

                if ($user_match) {
                    $this->logoutForm($form_state);
                } else {
                    // The user that the id_token_hint points to is not the same user as the one
                    // currently logged in.
                    $this->fatalError($this->f3->get('intl.common.already_logged_out'));
                }
            } elseif ($auth->isLoggedIn()) {
                // Prompt for log out
                $this->logoutForm($form_state);
            } else {
                // User has already been logged out
                $this->f3->set('message', $this->f3->get('intl.core.auth.logout_success'));
                $auth_module = $this->mgr->getModule('SimpleID\Auth\AuthModule');
                $auth_module->loginForm();
                return;
            }
        }
    }

    protected function logoutForm($form_state = []) {
        $tpl = new \Template();

        $token = new SecurityToken();
        $this->f3->set('tk', $token->generate('connect_logout', SecurityToken::OPTION_BIND_SESSION));
        $this->f3->set('fs', $token->generate($form_state));

        // logout_label is already defined in Module

        $this->f3->set('user_header', true);
        $this->f3->set('framekiller', true);
        $this->f3->set('title', $this->f3->get('intl.common.logout'));
        $this->f3->set('page_class', 'dialog-page');
        $this->f3->set('layout', 'connect_logout.html');
        
        header('X-Frame-Options: DENY');
        print $tpl->render('page.html');
    }

    /**
     * 
     */
    public function logoutComplete($f3, $params) {
        $token = new SecurityToken();

        $payload = $token->getPayload($params['token']);

        if ($payload === null) {
            $this->f3->fatalError($this->f3->get('intl.common.invalid_request'));
            return;
        }

        $response = new Response();
        if (isset($payload['state'])) $response['state'] = $payload['state'];
        $response->renderRedirect($payload['post_logout_redirect_uri']);
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
        return [
            'check_session_iframe' => $this->getCanonicalURL('@connect_check_session', '', 'https'),
            'end_session_endpoint' => $this->getCanonicalURL('@connect_logout', 'https')
        ];
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
