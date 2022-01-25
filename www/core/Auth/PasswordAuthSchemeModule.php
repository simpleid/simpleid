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

use \Bcrypt;
use Psr\Log\LogLevel;
use SimpleID\Auth\AuthManager;
use SimpleID\Store\StoreManager;
use SimpleID\Util\Events\BaseDataCollectionEvent;
use SimpleID\Util\Forms\FormBuildEvent;
use SimpleID\Util\Forms\FormSubmitEvent;

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
     * @param SimpleID\Util\Form\FormBuildEvent $event
     */
    public function onLoginFormBuild(FormBuildEvent $event) {
        $form_state = $event->getFormState();

        if ($form_state['mode'] == AuthManager::MODE_CREDENTIALS || $form_state['mode'] == AuthManager::MODE_REENTER_CREDENTIALS) {
            $tpl = new \Template();

            $this->f3->set('login_form_module', 'password');

            $event->addBlock('auth_password', $tpl->render('auth_password.html', false), 0);
        }
    }

    /**
     * Validates the login form.
     *
     * @param SimpleID\Util\Form\FormSubmitEvent $event
     */
    public function onLoginFormValidate(FormSubmitEvent $event) {
        $form_state = $event->getFormState();

        if ($form_state['mode'] == AuthManager::MODE_CREDENTIALS || $form_state['mode'] == AuthManager::MODE_REENTER_CREDENTIALS) {
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
     * @param SimpleID\Auth\LoginFormSubmitEvent $event
     */
    public function onLoginFormSubmit(LoginFormSubmitEvent $event) {
        $store = StoreManager::instance();
        $form_state = $event->getFormState();

        if ($form_state['mode'] == AuthManager::MODE_CREDENTIALS || $form_state['mode'] == AuthManager::MODE_REENTER_CREDENTIALS) {
            $uid = ($form_state['mode'] == AuthManager::MODE_CREDENTIALS) ? $this->f3->get('POST.uid') : $form_state['uid'];
            
            if ($this->verifyCredentials($uid, $this->f3->get('POST')) === false) {
                $this->f3->set('message', $this->f3->get('intl.core.auth_password.invalid_password'));
                $event->setInvalid();
                return;
            }

            $test_user = $store->loadUser($uid);

            $event->addAuthModuleName(self::class);
            $event->setUser($test_user);
            $event->setAuthLevel($form_state['mode']);
        }
    }

    /**
     * Verifies a set of credentials using the default user name-password authentication
     * method.
     *
     * @param string $uid the name of the user to verify
     * @param array $credentials the credentials supplied by the browser
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
                $bcrypt = Bcrypt::instance();
                return $bcrypt->verify($credentials['password']['password'], $test_user['password']['password']);
                break;
            case 'pbkdf2':
                $params = [];
                list($param_string, $hash, $salt) = explode('$', $content, 3);
                parse_str($param_string, $params);
                if (!isset($params['f'])) $params['f'] = 'sha256';
                if (!isset($params['dk'])) $params['dk'] = 0;
                return $this->secureCompare(hash_pbkdf2($params['f'], $credentials['password']['password'], base64_decode($salt), $params['c'], $params['dk'], true),
                    base64_decode($hash));
                break;
            default:
                $this->logger->log(LogLevel::WARNING, 'Unknown password prefix: ' . $prefix);
                return false;
        }
    }

    public function onUserSecretDataPaths(BaseDataCollectionEvent $event) {
        $event->addResult('password.password');
    }
}
?>