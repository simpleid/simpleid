<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2025
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

use \Bcrypt;
use Psr\Log\LogLevel;
use SimpleID\Auth\AuthManager;
use SimpleID\Auth\LoginFormBuildEvent;
use SimpleID\Store\StoreManager;
use SimpleID\Util\Events\BaseDataCollectionEvent;
use SimpleID\Util\Forms\FormSubmitEvent;
use SimpleID\Util\UI\Template;

/**
 * Password-based authentication scheme.
 *
 * This authentication scheme uses a user name and a password supplied
 * by the user.  A hash is generated from the password, which is compared
 * against the hash stored in the user store.
 *
 * Currently only bcrypt and pbkdf2 password hashing algorithms are
 * supported.
 */
class PasswordAuthSchemeModule extends AuthSchemeModule {
    /**
     * Displays the login form, with input fields for the user name
     * and password
     *
     * @param LoginFormBuildEvent $event
     * @return void
     */
    public function onLoginFormBuild(LoginFormBuildEvent $event) {
        $form_state = $event->getFormState();
        $additional = [];

        if ($form_state['mode'] == AuthManager::MODE_IDENTIFY_USER) {
            $event->showUIDBlock();
            $additional['region'] = LoginFormBuildEvent::PASSWORD_REGION;
        }

        if (in_array($form_state['mode'], [ AuthManager::MODE_IDENTIFY_USER, AuthManager::MODE_CREDENTIALS, AuthManager::MODE_REENTER_CREDENTIALS ])) {
            $tpl = Template::instance();

            $this->f3->set('login_form_module', 'password');

            $event->addBlock('auth_password', $tpl->render('auth_password.html', false), 0, $additional);
        }
    }

    /**
     * Validates the login form.
     *
     * @param FormSubmitEvent $event
     * @return void
     */
    public function onLoginFormValidate(FormSubmitEvent $event) {
        $form_state = $event->getFormState();

        if (($form_state['mode'] == AuthManager::MODE_CREDENTIALS || $form_state['mode'] == AuthManager::MODE_REENTER_CREDENTIALS) && $this->isBlockActive('auth_password')) {
            $uid = ($form_state['mode'] == AuthManager::MODE_CREDENTIALS) ? $this->f3->get('POST.uid') : $form_state['uid'];
            if (($uid === false) || ($uid === null)) $uid = '';

            if (($uid == '') || ($this->f3->exists('POST.password.password') === false)) {
                if ($this->f3->exists('PARAMS.continue')) {
                    // User came from a log in form.
                    $event->addMessage($this->f3->get('intl.core.auth_password.missing_password'));
                }
                $event->setInvalid();
            }
        }
    }

    /**
     * Processes the login form by verifying password credentials supplied
     * by the user.
     *
     * @param LoginFormSubmitEvent $event
     * @return void
     */
    public function onLoginFormSubmit(LoginFormSubmitEvent $event) {
        $store = StoreManager::instance();
        $form_state = $event->getFormState();

        if (($form_state['mode'] == AuthManager::MODE_CREDENTIALS || $form_state['mode'] == AuthManager::MODE_REENTER_CREDENTIALS) && $this->isBlockActive('auth_password')) {
            $uid = ($form_state['mode'] == AuthManager::MODE_CREDENTIALS) ? $this->f3->get('POST.uid') : $form_state['uid'];
            
            if ($this->verifyCredentials($uid, $this->f3->get('POST')) === false) {
                $event->addMessage($this->f3->get('intl.core.auth_password.invalid_password'));
                $event->setInvalid();
                return;
            }

            $test_user = $store->loadUser($uid);

            $event->addAuthModuleName(self::class);
            $event->setUser($test_user);
            $event->setAuthLevel(($form_state['mode'] == AuthManager::MODE_CREDENTIALS) ? AuthManager::AUTH_LEVEL_CREDENTIALS : AuthManager::AUTH_LEVEL_REENTER_CREDENTIALS);
        }
    }

    /**
     * @see SimpleID\Auth\LoginEvent
     * @return void
     */
    public function onLoginEvent(LoginEvent $event) {
        $user = $event->getUser();
        $level = $event->getAuthLevel();
        $store = StoreManager::instance();

        if ($level >= AuthManager::AUTH_LEVEL_CREDENTIALS) {
            $user->set('auth_login_last_active_block.' . AuthManager::MODE_CREDENTIALS, 'auth_password');
            $store->saveUser($user);
        }
    }

    /**
     * Verifies a set of credentials using the default user name-password authentication
     * method.
     *
     * @param string $uid the name of the user to verify
     * @param array<string, mixed> $credentials the credentials supplied by the browser
     * @return bool whether the credentials supplied matches those for the specified
     * user
     */
    protected function verifyCredentials($uid, $credentials) {
        $store = StoreManager::instance();

        $test_user = $store->loadUser($uid);
        if ($test_user == NULL) return false;

        list($dummy, $prefix, $content) = explode('$', $test_user['password']['password'], 3);
        if ($prefix == null) return false;

        switch ($prefix) {
            case '2y':
                return password_verify($credentials['password']['password'], $test_user['password']['password']);
            case 'pbkdf2':
                $params = [];
                list($param_string, $hash, $salt) = explode('$', $content, 3);
                parse_str($param_string, $params);
                if (!isset($params['f']) || is_array($params['f'])) $params['f'] = 'sha256';
                if (!isset($params['dk'])) $params['dk'] = 0;
                // @phpstan-ignore argument.type, argument.type, argument.type
                return $this->secureCompare(hash_pbkdf2(strval($params['f']), $credentials['password']['password'], base64_decode($salt), intval($params['c']), intval($params['dk']), true),
                    base64_decode($hash));
            default:
                $this->logger->log(LogLevel::WARNING, 'Unknown password prefix: ' . $prefix);
                return false;
        }
    }

    /**
     * @return void
     */
    public function onUserSecretDataPaths(BaseDataCollectionEvent $event) {
        $event->addResult('password.password');
    }
}
?>