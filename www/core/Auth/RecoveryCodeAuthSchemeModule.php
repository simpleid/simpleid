<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2026
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

use SimpleID\Auth\AuthManager;
use SimpleID\Crypt\Random;
use SimpleID\Crypt\SecurityToken;
use SimpleID\Store\StoreManager;
use SimpleID\Util\Events\BaseDataCollectionEvent;
use SimpleID\Util\Events\UIBuildEvent;
use SimpleID\Util\Forms\FormBuildEvent;
use SimpleID\Util\Forms\FormSubmitEvent;
use SimpleID\Util\UI\Template;

/**
 * An authentication scheme module that provides two-factor authentication
 * based on a RFC 6238 Time-Based One-Time Password (TOTP).
 */
class RecoveryCodeAuthSchemeModule extends AuthSchemeModule {

    const RECOVERY_CODE_COUNT = 5;
    const RECOVERY_CODE_MAX_ATTEMPTS = 5;
    const RECOVERY_CODE_TIMEOUT = 3600;

    const PBKDF2_ALGORITHM = 'sha256';
    const PBKDF2_ITERATIONS = 600000;

    static function init($f3) {
        $f3->route('POST @auth_recovery: /auth/recovery', 'SimpleID\Auth\RecoveryCodeAuthSchemeModule->setupRecoveryCodes');
    }

    /**
     * Displays the page used to set up login verification using one-time
     * passwords.
     * 
     * @return void
     */
    public function setupRecoveryCodes() {
        $auth = AuthManager::instance();
        $store = StoreManager::instance();
        /** @var \SimpleID\Models\User $user */
        $user = $auth->getUser();

        $tpl = Template::instance();
        $token = new SecurityToken();

        // Require HTTPS, redirect if necessary
        $this->checkHttps('redirect', true);
    
        if (!$auth->isLoggedIn()) {
            $this->f3->reroute('/my/dashboard');
            return;
        }

        // We check POST.active_block to see whether we are coming directly
        // from an authentication module
        if ($this->f3->exists('POST.active_block') && ($this->f3->get('POST.active_block') == 'auth_recovery') && $this->f3->get('POST.op') == 'continue') {
            $this->f3->set('message', $this->f3->get('intl.core.auth_recovery.generate_success'));
            $this->f3->mock('GET /my/dashboard');
            return;
        } elseif (($this->f3->exists('POST.active_block') && ($this->f3->get('POST.active_block') == 'auth_recovery') && $this->f3->get('POST.op') == 'reset')
            || !$user->exists('recovery.recovery_codes') || (count($user->get('recovery.recovery_codes')) == 0)) {

            if ($this->isBlockActive('auth_recovery') && (($this->f3->exists('POST.tk') === false) || (!$token->verify($this->f3->get('POST.tk'), 'recovery')))) {
                $this->f3->set('message', $this->f3->get('intl.common.invalid_tk'));
                $this->f3->mock('GET /my/dashboard');
                return;
            }

            $rand = new Random();
            $recovery_codes = [];
            $encoded_list = [];

            for ($i = 0; $i < self::RECOVERY_CODE_COUNT; $i++) {
                $code = $rand->password(32, 4, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
                $encoded_list[] = $this->encodeRecoveryCode($code);
                $recovery_codes[] = $code;
            }
            
            $user->set('recovery.recovery_codes', $encoded_list);
            $store->saveUser($user);

            $this->f3->set('recovery_codes', $recovery_codes);
        } elseif (!$this->f3->exists('POST.active_block') || ($this->f3->get('POST.active_block') != 'auth_recovery')) {
            // This is coming from another authentication scheme module.
            // Given recovery codes have already been set, we silently redirect
            // back to the dashboard
            $this->f3->mock('GET /my/dashboard');
            return;
        }
        
        $this->f3->set('tk', $token->generate('recovery', SecurityToken::OPTION_BIND_SESSION));

        $this->f3->set('page_class', 'is-dialog-page');
        $this->f3->set('title', $this->f3->get('intl.core.auth_recovery.recovery_title'));
        $this->f3->set('layout', 'auth_recovery_setup.html');

        header('X-Frame-Options: DENY');
        print $tpl->render('page.html');
    }

    /**
     * Returns the dashboard recovery code block.
     *
     * @param UIBuildEvent $event the event to collect
     * the dashboard recovery code block
     * @return void
     */
    public function onDashboardBlocks(UIBuildEvent $event) {
        $auth = AuthManager::instance();
        $user = $auth->getUser();

        $base_path = $this->f3->get('base_path');

        $token = new SecurityToken();
        $tk = $token->generate('recovery', SecurityToken::OPTION_BIND_SESSION);

        $html = '<p>' . $this->f3->get('intl.core.auth_recovery.about_recovery') . '</p>';

        if (isset($user['recovery'])) {
            $html .= '<p>' . $this->f3->get('intl.core.auth_recovery.recovery_codes_generated') . '</p>';
            $html .= '<form action="' . $base_path . 'auth/recovery" method="post" enctype="application/x-www-form-urlencoded"><input type="hidden" name="tk" value="'. $tk . '"/><input type="hidden" name="active_block" value="auth_recovery"/>';
            $html .= '<button type="submit" name="op" value="reset">' . $this->f3->get('intl.common.reset') . '</button></form>';
        } else {
            $html .= '<p>' . $this->f3->get('intl.core.auth_recovery.recovery_codes_not_generated') . '</p>';
            $html .= '<form action="' . $base_path . 'auth/recovery" method="post" enctype="application/x-www-form-urlencoded"><input type="hidden" name="tk" value="'. $tk . '"/><input type="hidden" name="active_block" value="auth_recovery"/>';
            $html .= '<button type="submit" name="op" value="reset">' . $this->f3->get('intl.core.auth_recovery.generate_recovery_code_button') . '</button></form>';
        }
        
        $event->addBlock('recovery', $html, 10, [
            'title' => $this->f3->get('intl.core.auth_recovery.recovery_title')
        ]);
    }

    /**
     * @param FormBuildEvent $event
     * @return void
     */
    public function onLoginFormBuild(FormBuildEvent $event) {
        $form_state = $event->getFormState();

        if ($form_state['mode'] == AuthManager::MODE_VERIFY) {
            $auth = AuthManager::instance();
            $store = StoreManager::instance();

            /** @var \SimpleID\Models\User $test_user */
            $test_user = $store->loadUser($form_state['uid']);
            if (!$test_user->exists('recovery.recovery_codes') || (count($test_user->get('recovery.recovery_codes')) == 0)) return;

            $tpl = Template::instance();

            $this->f3->set('submit_button', $this->f3->get('intl.common.verify'));

            $event->addBlock('auth_recovery', $tpl->render('auth_recovery.html', false), 10, ['title' => $this->f3->get('intl.core.auth_recovery.verify_block_title')]);
        }
    }

    /**
     * @param FormSubmitEvent $event
     * @return void
     */
    public function onLoginFormValidate(FormSubmitEvent $event) {
        $form_state = $event->getFormState();

        if (($form_state['mode'] == AuthManager::MODE_VERIFY) && $this->isBlockActive('auth_recovery')) {
            if ($this->f3->exists('POST.recovery.code') === false) {
                $event->addMessage($this->f3->get('intl.core.auth_recovery.missing_code'));
                $event->setInvalid();
            }
        }
    }

    /**
     * @param LoginFormSubmitEvent $event
     * @return void
     */
    public function onLoginFormSubmit(LoginFormSubmitEvent $event) {
        // Increment $form_state time and attempts

        $form_state = $event->getFormState();

        if (($form_state['mode'] == AuthManager::MODE_VERIFY) && $this->isBlockActive('auth_recovery')) {
            if ($form_state['recovery_attempts'] >= self::RECOVERY_CODE_MAX_ATTEMPTS) {
                if (time() > $form_state['recovery_attempt_time'] + self::RECOVERY_CODE_TIMEOUT) {
                    $form_state['recovery_attempts'] = 0;
                } else {
                    $event->addMessage($this->f3->get('intl.core.auth_recovery.too_many_attempts'));
                    $event->setInvalid();
                    return;
                }
            }

            $store = StoreManager::instance();

            $uid = $form_state['uid'];
            /** @var \SimpleID\Models\User $test_user */
            $test_user = $store->loadUser($form_state['uid']);

            if ($test_user->exists('recovery.recovery_codes') === false) {
                $event->addMessage($this->f3->get('intl.core.auth_recovery.invalid_code'));
                $event->setInvalid();
                return;
            }

            $encoded_list = $test_user->get('recovery.recovery_codes');

            // To mitigate against timing attacks, we check the codes at least RECOVERY_CODE_COUNT
            // times
            $count = max(count($encoded_list), self::RECOVERY_CODE_COUNT);
            $valid_code_index = -1;
            
            for ($i = 0; $i < $count; $i++) {
                $encoded = $encoded_list[$i % count($encoded_list)];
                if ($this->verifyRecoveryCode($this->f3->get('POST.recovery.code'), $encoded)) $valid_code_index = $i;
            }
            
            if ($valid_code_index == -1) {
                if (isset($form_state['recovery_attempts'])) {
                    $form_state['recovery_attempts'] += 1;
                } else {
                    $form_state['recovery_attempts'] = 1;
                }
                $form_state['recovery_attempt_time'] = time();
                $event->addMessage($this->f3->get('intl.core.auth_recovery.invalid_code'));
                $event->setInvalid();
                return;
            }

            // Remove successful code from list and save
            array_splice($encoded_list, $valid_code_index, 1);
            $test_user->set('recovery.recovery_codes', $encoded_list);
            $store->saveUser($test_user); // Save the drift

            $event->addAuthModuleName(self::class);
            $event->setUser($test_user);
            $event->setAuthLevel(AuthManager::AUTH_LEVEL_VERIFIED);

            $event->addMessage($this->f3->get('intl.core.auth_recovery.code_used'));
        }
    }

    /**
     * Hashes and encodes a recovery code using PBKDF2.
     * 
     * @param string $code the recovery code
     * @return string the encoded hash value
     */
    protected function encodeRecoveryCode(#[\SensitiveParameter] string $code): string {
        $rand = new Random();
        $salt = $rand->bytes(32);
        $params = [ 'f' => self::PBKDF2_ALGORITHM, 'c' => self::PBKDF2_ITERATIONS ];
        $hash = hash_pbkdf2(strval($params['f']), $code, $salt, intval($params['c']), 0, true);
        
        return '$pbkdf2$' . http_build_query($params) . '$' . base64_encode($hash) . '$' . base64_encode($salt);
    }

    /**
     * Verifies whether a specified recovery code matches the specified encode value.
     *
     * @param string $code the recovery code to verify
     * @param string $encoded the encoded value
     * @return bool whether the recovery code supplied matches the specified encoded
     * value
     */
    protected function verifyRecoveryCode(#[\SensitiveParameter] string $code, string $encoded): bool {
        list($dummy, $prefix, $content) = explode('$', $encoded, 3);
        if ($prefix != 'pbkdf2') return false;

        $params = [];
        list($param_string, $hash, $salt) = explode('$', $content, 3);
        parse_str($param_string, $params);
        if (!isset($params['f']) || ($params['f'] != self::PBKDF2_ALGORITHM)) return false;
        // @phpstan-ignore argument.type, argument.type
        return $this->secureCompare(hash_pbkdf2(strval($params['f']), $code, base64_decode($salt), intval($params['c']), 0, true),
            base64_decode($hash));
    }

    /**
     * @return void
     */    
    public function onUserSecretDataPaths(BaseDataCollectionEvent $event) {
        $event->addResult('recovery.recovery_codes');
    }
}
?>
