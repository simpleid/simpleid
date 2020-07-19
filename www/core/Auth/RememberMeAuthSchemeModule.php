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

namespace SimpleID\Auth;

use Psr\Log\LogLevel;
use SimpleID\Crypt\Random;
use SimpleID\Store\StoreManager;
use SimpleID\Util\SecurityToken;

/**
 * An authentication scheme that provides automatic authentication
 * via a cookie stored in the user agent.
 */
class RememberMeAuthSchemeModule extends AuthSchemeModule {
    /** The name of the cookie */
    protected $cookie_name;

    public function __construct() {
        parent::__construct();
        $this->cookie_name = $this->auth->getCookieName('auth');
    }

    /**
     * Attempts to automatically login using the auto login cookie
     * 
     * @see SimpleID\API\AuthHooks::autoAuthHook()
     * @return SimpleID\Models\User the user object, or NULL
     */
    public function autoAuthHook() {
        if (!$this->f3->exists('COOKIE.' . $this->cookie_name)) return null;
       
        $cookie = $this->f3->get('COOKIE.' . $this->cookie_name);

        $token = new SecurityToken();
        $data = $token->getPayload($cookie);

        if ($data === null) {
            $this->logger->log(LogLevel::NOTICE, 'Automatic login: Invalid token - clearing');
            $this->logoutHook();
            return null;
        }
    
        if ($data['typ'] != 'rememberme') return NULL;

        $this->logger->log(LogLevel::DEBUG, 'Automatic login token detected', $data);
    
        if ($data['exp'] < time()) {  // Cookie expired
            $this->logger->log(LogLevel::NOTICE, 'Automatic login: Expired - clearing');
            $this->logoutHook();
            return NULL;
        }

        if ($data['uaid'] != $this->auth->assignUAID()) {
            $this->logger->log(LogLevel::WARNING, 'Automatic login: User agent ID does not match - clearing');
            $this->logoutHook();
            return NULL;
        }

        $store = StoreManager::instance();

        // Load the user, tag it as an auto log in
        $test_user = $store->loadUser($data['uid']);
        
        if ($test_user != NULL) {
            $this->logger->log(LogLevel::INFO, 'Automatic login token accepted for ' . $data['uid']);
            
            return $test_user;
        } else {
            $this->logger->log(LogLevel::WARNING, 'Automatic login token accepted for ' . $data['uid'] . ', but no such user exists');
            return NULL;
        }
    }

    /**
     * Displays the login form, with a remember-me checkbox.
     *
     * @param array &$form_state
     * @return array
     */
    public function loginFormHook(&$form_state) {
        if ($form_state['mode'] == AuthManager::MODE_CREDENTIALS) {
            $tpl = new \Template();

            $this->f3->set('rememberme_label', $this->t('Remember me on this device for two weeks.'));

            return [
                [
                    'content' => $tpl->render('auth_rememberme.html', false),
                    'weight' => 10
                ]
            ];
        }
    }

    /**
     * Processes the login form by storing the user's remember-me setting
     * in the form state.
     *
     * @param array &$form_state
     * @return bool|array
     */
    public function loginFormSubmitHook(&$form_state) {
        if ($form_state['mode'] == AuthManager::MODE_CREDENTIALS) {
            if ($this->f3->exists('POST.rememberme') === true) {
                $form_state['rememberme'] = $this->f3->get('POST.rememberme');
            }
        }
    }

    /**
     * Completes the login process by issuing a auto login cookie (if
     * so selected by the user).
     *
     * @param User $user
     * @param int $level
     * @param array $modules
     * @param array $form_state
     */
    public function loginHook($user, $level, $modules, $form_state) {
        if (($level == AuthManager::MODE_CREDENTIALS) && isset($form_state['rememberme']) && ($form_state['rememberme'] == 1)) {
            $this->createCookie();
        }
    }

    /**
     * Removes the auto login cookie from the user agent.
     *
     * @see SimpleID\API\AuthHooks::logoutHook()
     */
    public function logoutHook($user) {
        if ($this->f3->exists('COOKIE.' . $this->cookie_name)) {
            $cookie = $this->f3->clear('COOKIE.' . $this->cookie_name);
        }
    }

    /**
     * Creates a auto login cookie.  The login cookie will be based on the
     * current log in user.
     *
     * @param string $id the ID of the series of auto login cookies,  Cookies
     * belonging to the same user and computer have the same ID.  If none is specified,
     * one will be generated
     * @param int $expires the time at which the cookie will expire.  If none is specified
     * the time specified in {@link SIMPLEID_REMEMBERME_EXPIRES_IN} will be
     * used
     *
     */
    protected function createCookie($id = NULL, $expires = NULL) {
        $user = $this->auth->getUser();

        $rand = new Random();
        
        if ($expires == NULL) {
            $this->logger->log(LogLevel::DEBUG, 'Automatic login token created for ' . $user['uid']);
        } else {
            $this->logger->log(LogLevel::DEBUG, 'Automatic login token renewed for ' . $user['uid']);
        }
        
        if ($id == NULL) $id = $rand->id();
        
        if ($expires == NULL) $expires = time() + SIMPLEID_LONG_TOKEN_EXPIRES_IN;

        $data = [
            'typ' => 'rememberme',
            'id' => $id,
            'uid' => $user['uid'],
            'exp' => $expires,
            'uaid' => $this->auth->assignUAID(),
        ];
        
        $token = new SecurityToken();
        $cookie = $token->generate($data);
        
        $this->f3->set('COOKIE.' . $this->cookie_name, $cookie, SIMPLEID_LONG_TOKEN_EXPIRES_IN);
    }
}
?>