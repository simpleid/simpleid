<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2024
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
use SimpleID\Util\Events\BaseStoppableEvent;
use SimpleID\Util\Forms\FormState;
use SimpleID\Util\Forms\FormBuildEvent;
use SimpleID\Util\Forms\FormSubmitEvent;
use SimpleID\Util\UI\Template;

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
    /** @var AuthManager */
    private $auth;

    static function init($f3) {
        $f3->route('GET|POST /auth/login', 'SimpleID\Auth\AuthModule->login');
        $f3->route('GET|POST @auth_login: /auth/login/*', 'SimpleID\Auth\AuthModule->login');
        $f3->route('GET /auth/logout', 'SimpleID\Auth\AuthModule->logout');
        $f3->route('GET @auth_logout: /auth/logout/*', 'SimpleID\Auth\AuthModule->logout');
    }

    public function __construct() {
        parent::__construct();
        $this->auth = AuthManager::instance();
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
     * @param array<string, mixed> $params
     * @return void
     */
    public function login($f3, $params) {
        $dispatcher = \Events::instance();

        $params['destination'] = (isset($params['*'])) ? $params['*'] : '';
        $this->f3->set('PARAMS.destination', $params['destination']);

        $token = new SecurityToken();

        // Require HTTPS or return an error
        $this->checkHttps('error', true);

        if (($this->f3->exists('POST.fs') === false)) {
            $form_state = new FormState([ 'mode' => AuthManager::MODE_CREDENTIALS ]);
            if (in_array($this->f3->get('GET.mode'), [ AuthManager::MODE_VERIFY, AuthManager::MODE_REENTER_CREDENTIALS ])) {
                $form_state['mode'] = $this->f3->get('GET.mode');
            }
            $this->loginForm($params, $form_state);
            return;
        }

        $form_state = FormState::decode($token->getPayload($this->f3->get('POST.fs')));
        if (count($form_state) == 0) $form_state['mode'] = AuthManager::MODE_CREDENTIALS;
        $mode = $form_state['mode'];
        if (!in_array($mode, [ AuthManager::MODE_CREDENTIALS, AuthManager::MODE_REENTER_CREDENTIALS, AuthManager::MODE_VERIFY ])) {
            $this->f3->set('message', $this->f3->get('intl.core.auth.state_error'));
            $this->loginForm($params, $form_state);
            return;
        }

        if ($this->f3->exists('POST.tk') === false) {
            if ($params['destination']) {
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
            $cancel_event = new FormSubmitEvent($form_state, 'login_form_cancel');

            $dispatcher->dispatch($cancel_event);

            // Listeners should call stopPropagation if it has processed successfully
            if (!$cancel_event->isPropagationStopped()) {
                $this->fatalError($this->f3->get('intl.core.auth.cancelled'), 400);
            }
            return;
        }

        // If the user is already logged in, return
        if (($mode == AuthManager::MODE_CREDENTIALS) && $this->auth->isLoggedIn()) $this->f3->reroute('/');

        $validate_event = new FormSubmitEvent($form_state, 'login_form_validate');
        $dispatcher->dispatch($validate_event);
        if (!$validate_event->isValid()) {
            $this->f3->set('message', $validate_event->getMessages());
            $this->loginForm($params, $form_state);
            return;
        }

        $submit_event = new LoginFormSubmitEvent($form_state, 'login_form_submit');
        $dispatcher->dispatch($submit_event);
        if (!$submit_event->isValid()) {
            $this->f3->set('message', $submit_event->getMessages());
            $this->loginForm($params, $form_state);
            return;
        }

        if ($submit_event->isAuthSuccessful()) {
            // $submit_event->getUser() can be null when mode is MODE_VERIFY or MODE_REENTER_CREDENTIALS
            // In these cases $form_state['uid'] would already be populated
            $test_user = $submit_event->getUser();
            if ($test_user != null) $form_state['uid'] = $test_user['uid'];

            $form_state['auth_level'] = $submit_event->getAuthLevel();
            $form_state['modules'] = $submit_event->getAuthModuleNames();
        } else {
            $this->loginForm($params, $form_state);
            return;
        }

        if (!isset($form_state['uid'])) {
            // No user
            $this->loginForm($params, $form_state);
            return;
        }

        if ($mode == AuthManager::MODE_CREDENTIALS) {
            $form_state['mode'] = AuthManager::MODE_VERIFY;
            $event = new FormBuildEvent($form_state, 'login_form_build');

            $dispatcher->dispatch($event);
            if (count($event->getBlocks()) > 0) {
                $this->loginForm($params, $form_state);
                return;
            }
        }
        
        $this->auth->login($submit_event, $form_state);
        
        $this->f3->reroute('/' . $params['destination']);
    }

    /**
     * Attempts to log out a user and returns to the login form.
     *
     * @param \Base $f3
     * @param array<string, mixed> $params
     * @return void
     */
    public function logout($f3, $params) {
        $params['destination'] = (isset($params['*'])) ? $params['*'] : '';
        $this->f3->set('PARAMS.destination', $params['destination']);

        // Require HTTPS, redirect if necessary
        $this->checkHttps('redirect', true);
    
        $this->auth->logout();

        $event = new BaseStoppableEvent('post_logout');
        \Events::instance()->dispatch($event);

        if (!$event->isPropagationStopped()) {
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
     * @param array<string, mixed> $params the F3 parameters
     * @param FormState $form_state|null the form state
     * @return void
     */
    public function loginForm($params = [ 'destination' => null ], $form_state = null) {
        $tpl = Template::instance();
        $config = $this->f3->get('config');
        if ($form_state == null) $form_state = new FormState([ 'mode' => AuthManager::MODE_CREDENTIALS ]);

        // 1. Check for HTTPS
        $this->checkHttps('redirect', true);

        // 2. Build the forms
        if (($form_state['mode'] == AuthManager::MODE_VERIFY) && isset($form_state['verify_forms'])) {
            $forms = $form_state['verify_forms'];
            unset($form_state['verify_forms']);
        } else {
            $event = new FormBuildEvent($form_state, 'login_form_build');
            \Events::instance()->dispatch($event);
            $forms = $event->getBlocks();
            $tpl->mergeAttachments($event);
        }
        $this->f3->set('forms', $forms);

        // 3. Build the buttons and security messaging
        switch ($form_state['mode']) {
            case AuthManager::MODE_REENTER_CREDENTIALS:
                // Follow through
                $this->f3->set('uid', $form_state['uid']);
            case AuthManager::MODE_CREDENTIALS:
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

        // 4. We can't use SecurityToken::BIND_SESSION here because the PHP session is not
        // yet stable
        $token = new SecurityToken();
        $this->f3->set('tk', $token->generate('login', SecurityToken::OPTION_NONCE));
        
        $this->f3->set('fs', $token->generate($form_state->encode()));
        if (isset($params['destination'])) $this->f3->set('destination', $params['destination']);
        $this->f3->set('page_class', 'is-dialog-page');
        $this->f3->set('layout', 'auth_login.html');

        header('X-Frame-Options: DENY');
        print $tpl->render('page.html');
    }
}

?>