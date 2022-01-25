<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2022
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
use SimpleID\Auth\AutoAuthEvent;
use SimpleID\Crypt\Random;
use SimpleID\Store\StoreManager;
use SimpleID\Util\SecurityToken;
use SimpleID\Util\Forms\FormBuildEvent;

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
     * @see SimpleID\Auth\AutoAuthEvent
     */
    public function onAutoAuthEvent(AutoAuthEvent $event) {
        if (!$this->f3->exists('COOKIE.' . $this->cookie_name)) return null;
       
        $cookie = $this->f3->get('COOKIE.' . $this->cookie_name);

        $token = new SecurityToken();
        $data = $token->getPayload($cookie);

        if ($data === null) {
            $this->logger->log(LogLevel::NOTICE, 'Automatic login: Invalid token - clearing');
            $this->removeCookie();
            return null;
        }
    
        if ($data['typ'] != 'rememberme') return NULL;

        $this->logger->log(LogLevel::DEBUG, 'Automatic login token detected', $data);
    
        if ($data['exp'] < time()) {  // Cookie expired
            $this->logger->log(LogLevel::NOTICE, 'Automatic login: Expired - clearing');
            $this->removeCookie();
            return NULL;
        }

        if ($data['uaid'] != $this->auth->assignUAID()) {
            $this->logger->log(LogLevel::WARNING, 'Automatic login: User agent ID does not match - clearing');
            $this->removeCookie();
            return NULL;
        }

        $store = StoreManager::instance();

        // Load the user, tag it as an auto log in
        $test_user = $store->loadUser($data['uid']);
        
        if ($test_user != NULL) {
            $this->logger->log(LogLevel::INFO, 'Automatic login token accepted for ' . $data['uid']);
            $event->setUser($test_user, static::class);
        } else {
            $this->logger->log(LogLevel::WARNING, 'Automatic login token accepted for ' . $data['uid'] . ', but no such user exists');
        }
    }

    /**
     * Displays the login form, with a remember-me checkbox.
     *
     * @param SimpleID\Util\Form\FormBuildEvent $event
     */
    public function onLoginFormBuild(FormBuildEvent $event) {
        $form_state = $event->getFormState();

        if ($form_state['mode'] == AuthManager::MODE_CREDENTIALS) {
            $tpl = new \Template();
            $event->addBlock('auth_rememberme', $tpl->render('auth_rememberme.html', false), 10);
        }
    }

    /**
     * Processes the login form by storing the user's remember-me setting
     * in the form state.
     *
     * @param SimpleID\Auth\LoginFormSubmitEvent $event
     */
    public function onLoginFormSubmit(LoginFormSubmitEvent $event) {
        $form_state = $event->getFormState();

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
     * @see SimpleID\Auth\LoginEvent
     */
    public function onLoginEvent(LoginEvent $event) {
        $level = $event->getAuthLevel();
        $form_state = $event->getFormState();

        if (($level == AuthManager::MODE_CREDENTIALS) && isset($form_state['rememberme']) && ($form_state['rememberme'] == 1)) {
            $this->createCookie();
        }
    }


    public function onLogoutEvent(LogoutEvent $event) {
        $this->removeCookie();
    }

    /**
     * Removes the auto login cookie from the user agent.
     *
     */
    public function removeCookie() {
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