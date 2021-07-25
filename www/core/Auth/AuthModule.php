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
use SimpleID\Module;
use SimpleID\ModuleManager;
use SimpleID\Util\SecurityToken;

/**
 * The module used to authenticate users.
 *
 * This module delegates the actual authentication function to
 * other modules, using various hooks.  Details of the hooks can be
 * found in the API documention found in the See link
 *
 * @see SimpleID\API\AuthHooks
 */
class AuthModule extends Module {

    private $auth;
    private $mgr;

    static function routes($f3) {
        $f3->route('GET|POST /auth/login', 'SimpleID\Auth\AuthModule->login');
        $f3->route('GET|POST @auth_login: /auth/login/*', 'SimpleID\Auth\AuthModule->login');
        $f3->route('GET /auth/logout', 'SimpleID\Auth\AuthModule->logout');
        $f3->route('GET @auth_logout: /auth/logout/*', 'SimpleID\Auth\AuthModule->logout');
    }

    public function __construct() {
        parent::__construct();
        $this->auth = AuthManager::instance();
        $this->mgr = ModuleManager::instance();
    }

    /**
     * FatFree Framework event handler.
     *
     * This module does not use the default event handler provided by {@link SimpleID\Module},
     * as it needs to disable the automatic authentication.
     *
     */
    public function beforeroute() {
        $this->auth->initSession();
        $this->auth->initUser(false);
    }

    /**
     * Attempts to log in a user, using the credentials specified in the
     * HTTP request.
     *
     * @param \Base $f3
     * @param array $params
     */
    public function login($f3, $params) {
        $params['destination'] = (isset($params[1])) ? $params[1] : '';
        $this->f3->set('PARAMS.destination', $params['destination']);

        $token = new SecurityToken();

        // Require HTTPS or return an error
        $this->checkHttps('error', true);

        if (($this->f3->exists('POST.fs') === false)) {
            $form_state = [ 'mode' => AuthManager::MODE_CREDENTIALS ];
            if (in_array($this->f3->get('GET.mode'), [ AuthManager::MODE_VERIFY, AuthManager::MODE_REENTER_CREDENTIALS ])) {
                $form_state['mode'] = $this->f3->get('GET.mode');
            }
            $this->loginForm($params, $form_state);
            return;
        }

        $form_state = $token->getPayload($this->f3->get('POST.fs'));
        if ($form_state === false) $form_state = [ 'mode' => AuthManager::MODE_CREDENTIALS ];
        $mode = $form_state['mode'];
        if (!in_array($mode, [ AuthManager::MODE_CREDENTIALS, AuthManager::MODE_REENTER_CREDENTIALS, AuthManager::MODE_VERIFY ])) {
            $this->f3->set('message', $this->f3->get('intl.core.auth.state_error'));
            $this->loginForm($params, $form_state);
            return;
        }

        if ($this->f3->exists('POST.tk') === false) {
            if (isset($params['destination'])) {
                // User came from a log in form.
                $this->f3->set('message', $this->f3->get('intl.core.auth.missing_tk'));
            }
            $this->loginForm($params, $form_state);
            return;
        }

        if (!$token->verify($this->f3->get('POST.tk'), 'login')) {
            $this->logger->log(LogLevel::WARNING, 'Login attempt: Security token ' . $this->f3->get('POST.tk') . ' invalid.');
            $this->f3->set('message', $this->f3->get('intl.core.auth.state_error'));
            $this->loginForm($params, $form_state);
            return;
        }

        if ($this->f3->exists('POST.op') && $this->f3->get('POST.op') == $this->f3->get('intl.common.cancel')) {
            $results = $this->mgr->invokeAll('loginFormCancelled', $form_state);
            
            if (!array_reduce($results, function($overall, $result) { return ($result) ? true : $overall; }, false)) {
                $this->fatalError($this->f3->get('intl.core.auth.cancelled'));
            }
            return;
        }

        // If the user is already logged in, return
        if (($mode == AuthManager::MODE_CREDENTIALS) && $this->auth->isLoggedIn()) $this->f3->reroute('/');

        $results = $this->mgr->invokeRefAll('loginFormValidate', $form_state);
        if (!array_reduce($results, function($overall, $result) { return (($result !== null) && ($result === false)) ? false : $overall; }, true)) {
            $this->loginForm($params, $form_state);
            return;
        }

        $modules = $this->mgr->getModules();
        foreach ($modules as $module) {
            $results = $this->mgr->invokeRef($module, 'loginFormSubmit', $form_state);
            if ($results === false) {
                $this->loginForm($params, $form_state);
                return;
            }
            if (is_array($results)) {
                if (isset($results['uid'])) $form_state['uid'] = $results['uid'];
                if (isset($results['auth_level'])) {
                    $form_state['auth_level'] = (isset($form_state['auth_level'])) ? max($form_state['auth_level'], $results['auth_level']) : $results['auth_level'];
                }
                if (!isset($form_state['modules'])) $form_state['modules'] = [];
                $form_state['modules'][] = $module;
            }
        }

        if (!isset($form_state['uid'])) {
            // No user
            $this->loginForm($params, $form_state);
            return;
        }

        if ($mode == AuthManager::MODE_CREDENTIALS) {
            $form_state['mode'] = AuthManager::MODE_VERIFY;
            $forms = $this->mgr->invokeRefAll('loginForm', $form_state);
            if (count($forms) > 0) {
                $this->loginForm($params, $form_state);
                return;
            }
        }
        
        $this->auth->login($form_state['uid'], $form_state['auth_level'], $form_state['modules'], $form_state);
        
        $this->f3->reroute('/' . $params['destination']);
    }

    /**
     * Attempts to log out a user and returns to the login form.
     *
     * @param \Base $f3
     * @param array $params
     */
    public function logout($f3, $params) {
        $params['destination'] = (isset($params[1])) ? $params[1] : '';
        $this->f3->set('PARAMS.destination', $params['destination']);

        // Require HTTPS, redirect if necessary
        $this->checkHttps('redirect', true);
    
        $this->auth->logout();

        $results = $this->mgr->invokeAll('logoutComplete');

        if (!$results) {
            if ($params['destination']) {
                $this->f3->reroute('/' . $params['destination']);
            } else {
                $this->f3->set('message', $this->f3->get('intl.core.auth.logout_success'));
                $this->loginForm($params);
            }
        }
    }

    /**
     * Displays a user login or a login verification form.
     *
     * @param array $params the F3 parameters
     * @param array $form_state the form state
     */
    public function loginForm($params = [ 'destination' => null ], $form_state = [ 'mode' => AuthManager::MODE_CREDENTIALS ]) {
        $tpl = new \Template();
        $config = $this->f3->get('config');

        // 1. Check for HTTPS
        $this->checkHttps('redirect', true);

        // 2. Build the buttons and security messaging
        switch ($form_state['mode']) {
            case AuthManager::MODE_REENTER_CREDENTIALS:
                // Follow through
                $this->f3->set('uid', $form_state['uid']);
            case AuthManager::MODE_CREDENTIALS:
                $security_class = ($config['allow_autocomplete']) ? 'allow-autocomplete ' : '';
                $this->f3->set('security_class', $security_class);

                $this->f3->set('submit_button', $this->f3->get('intl.common.login'));
                $this->f3->set('title', $this->f3->get('intl.common.login'));
                break;
            case AuthManager::MODE_VERIFY:
                if (count($forms) == 0) return; // Nothing to verify
                $this->f3->set('submit_button', $this->f3->get('intl.common.verify'));
                $this->f3->set('title', $this->f3->get('intl.common.verify'));
        }

        if (isset($form_state['cancel'])) {
            $this->f3->set('cancellable', true);
        }

        // 3. Build the forms
        if (($form_state['mode'] == AuthManager::MODE_VERIFY) && isset($form_state['verify_forms'])) {
            $forms = $form_state['verify_forms'];
            unset($form_state['verify_forms']);
        } else {
            $forms = $this->mgr->invokeRefAll('loginForm', $form_state);
            uasort($forms, function($a, $b) { if ($a['weight'] == $b['weight']) { return 0; } return ($a['weight'] < $b['weight']) ? -1 : 1; });
        }
        $this->f3->set('forms', $forms);

        // 4. We can't use SecurityToken::BIND_SESSION here because the PHP session is not
        // yet stable
        $token = new SecurityToken();
        $this->f3->set('tk', $token->generate('login', SecurityToken::OPTION_NONCE));
        
        $this->f3->set('fs', $token->generate($form_state));
        if (isset($params['destination'])) $this->f3->set('destination', $params['destination']);
        $this->f3->set('framekiller', true);
        $this->f3->set('page_class', 'dialog-page');
        $this->f3->set('layout', 'auth_login.html');

        header('X-Frame-Options: DENY');
        print $tpl->render('page.html');
    }
}

?>