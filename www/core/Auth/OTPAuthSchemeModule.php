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

use Psr\Log\LogLevel;
use SimpleID\Auth\AuthManager;
use SimpleID\Crypt\BigNum;
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
class OTPAuthSchemeModule extends AuthSchemeModule {

    static function init($f3) {
        $f3->route('GET|POST /auth/otp', 'SimpleID\Auth\OTPAuthSchemeModule->setup');
    }

    /**
     * Displays the page used to set up login verification using one-time
     * passwords.
     * 
     * @return void
     */
    public function setup() {
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

        if ($this->f3->get('POST.op') == 'disable') {
            if (($this->f3->exists('POST.tk') === false) || (!$token->verify($this->f3->get('POST.tk'), 'otp'))) {
                $this->f3->set('message', $this->f3->get('intl.common.invalid_tk'));
                $this->f3->mock('GET /my/dashboard');
                return;
            }

            if (isset($user['otp'])) {
                unset($user['otp']);
                $store->saveUser($user);

                $event = new CredentialEvent($user, CredentialEvent::CREDENTIAL_DELETED_EVENT, self::class);
                \Events::instance()->dispatch($event);
            }
            $this->f3->set('message', $this->f3->get('intl.core.auth_otp.disable_success'));
            $this->f3->mock('GET /my/dashboard');
            return;
        } elseif ($this->f3->get('POST.op') == 'verify') {
            $params = $token->getPayload($this->f3->get('POST.otp_params'));
            $params['secret'] = base64_decode($params['secret']);
            $this->f3->set('otp_params', $this->f3->get('POST.otp_params'));

            if (($this->f3->exists('POST.tk') === false) || (!$token->verify($this->f3->get('POST.tk'), 'otp'))) {
                $this->f3->set('message', $this->f3->get('intl.common.invalid_tk'));
                $this->f3->mock('GET /my/dashboard');
                return;
            } elseif (($this->f3->exists('POST.otp') === false) || ($this->f3->get('POST.otp') == '')) {
                $this->f3->set('message', $this->f3->get('intl.core.auth_otp.missing_otp'));
            } elseif ($this->verifyOTP($params, $this->f3->get('POST.otp'), 10) === false) {
                $this->f3->set('message', $this->f3->get('intl.core.auth_otp.invalid_otp'));
            } else {
                $user['otp'] = $params;
                $store->saveUser($user);

                $event = new CredentialEvent($user, CredentialEvent::CREDENTIAL_ADDED_EVENT, self::class);
                \Events::instance()->dispatch($event);

                $this->f3->set('message', $this->f3->get('intl.core.auth_otp.enable_success'));
                $this->f3->mock('GET /my/dashboard');
                return;
            }
        } else {
            $rand = new Random();

            $params = [
                'type' => 'totp',
                'secret' => $rand->bytes(10),
                'algorithm' => 'sha1',
                'digits' => 6,
                'period' => 30,
                'drift' => 0,
                'remember' => []
            ];
            // SecurityToken requires everything to be UTF-8
            $params_token = $params;
            $params_token['secret'] = base64_encode($params['secret']);
            $this->f3->set('otp_params', $token->generate($params_token, SecurityToken::OPTION_BIND_SESSION));
        }

        $secret = new BigNum($params['secret'], 256);
        $base32 = $secret->val(32);
        assert($base32 != false);
        $code = strtr($base32, '0123456789abcdefghijklmnopqrstuv', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
        $code = str_repeat('A', 16 - strlen($code)) . $code;
        for ($i = 0; $i < strlen($code); $i += 4) {
            $this->f3->set('secret' . ($i + 1), substr($code, $i, 4));
        }

        $url = 'otpauth://totp/SimpleID:' . rawurlencode($user['uid']) . '?issuer=SimpleID&secret=' . $code . '&digits=' . $params['digits'] . '&period=' . $params['period'];
        $this->f3->set('qr', addslashes($url));

        $this->f3->set('otp_recovery_url', 'http://simpleid.org/docs/2/common-problems/#otp');
        
        $this->f3->set('tk', $token->generate('otp', SecurityToken::OPTION_BIND_SESSION));


        $this->f3->set('page_class', 'is-dialog-page');
        $this->f3->set('title', $this->f3->get('intl.core.auth_otp.otp_title'));
        $this->f3->set('layout', 'auth_otp_setup.html');

        header('X-Frame-Options: DENY');
        print $tpl->render('page.html');
    }

    /**
     * Returns the dashboard OTP block.
     *
     * @param UIBuildEvent $event the event to collect
     * the dashboard OTP block
     * @return void
     */
    public function onDashboardBlocks(UIBuildEvent $event) {
        $auth = AuthManager::instance();
        $user = $auth->getUser();

        $base_path = $this->f3->get('base_path');

        $token = new SecurityToken();
        $tk = $token->generate('otp', SecurityToken::OPTION_BIND_SESSION);

        $html = '<p>' . $this->f3->get('intl.core.auth_otp.about_otp') . '</p>';

        if (isset($user['otp'])) {
            $html .= '<p>' . $this->f3->get('intl.core.auth_otp.otp_enabled_block') . '</p>';
            $html .= '<form action="' . $base_path . 'auth/otp" method="post" enctype="application/x-www-form-urlencoded"><input type="hidden" name="tk" value="'. $tk . '"/>';
            $html .= '<button type="submit" name="op" value="disable">' . $this->f3->get('intl.common.disable') . '</button></form>';
        } else {
            $html .= '<p>' . $this->f3->get('intl.core.auth_otp.otp_disabled_block') . '</p>';
            $html .= '<form action="' . $base_path . 'auth/otp" method="post" enctype="application/x-www-form-urlencoded"><input type="hidden" name="tk" value="'. $tk . '"/>';
            $html .= '<button type="submit" name="op" value="enable">' . $this->f3->get('intl.common.enable') . '</button></form>';
        }
        
        $event->addBlock('otp', $html, 0, [
            'title' => $this->f3->get('intl.core.auth_otp.otp_title')
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
            if (!isset($test_user['otp'])) return;
            if ($test_user['otp']['type'] == 'recovery') return;

            $uaid = $auth->assignUAID();
            if (in_array($uaid, $test_user['otp']['remember'])) return;

            $tpl = Template::instance();

            // Note this is called from user_login(), so $_POST is always filled
            $this->f3->set('otp_recovery_url', 'http://simpleid.org/docs/2/common_problems/#otp');

            $this->f3->set('submit_button', $this->f3->get('intl.common.verify'));

            $event->addBlock('auth_otp', $tpl->render('auth_otp.html', false), 0);
        }
    }

    /**
     * @param FormSubmitEvent $event
     * @return void
     */
    public function onLoginFormValidate(FormSubmitEvent $event) {
        $form_state = $event->getFormState();

        if ($form_state['mode'] == AuthManager::MODE_VERIFY) {
            if ($this->f3->exists('POST.otp.otp') === false) {
                $this->f3->set('message', $this->f3->get('intl.core.auth_otp.missing_otp'));
                $event->setInvalid();
            }
        }
    }

    /**
     * @param LoginFormSubmitEvent $event
     * @return void
     */
    public function onLoginFormSubmit(LoginFormSubmitEvent $event) {
        $form_state = $event->getFormState();

        if ($form_state['mode'] == AuthManager::MODE_VERIFY) {
            $store = StoreManager::instance();

            $uid = $form_state['uid'];
            /** @var \SimpleID\Models\User $test_user */
            $test_user = $store->loadUser($form_state['uid']);
            $params = $test_user['otp'];
            
            if ($this->verifyOTP($params, $this->f3->get('POST.otp.otp'), 10) === false) {
                $this->f3->set('message', $this->f3->get('intl.core.auth_otp.invalid_otp'));
                $event->setInvalid();
                return;
            }

            if ($this->f3->get('POST.otp.remember') == '1') $form_state['otp_remember'] = 1;

            $test_user['otp'] = $params;
            $store->saveUser($test_user); // Save the drift

            $event->addAuthModuleName(self::class);
            $event->setUser($test_user);
            $event->setAuthLevel(AuthManager::AUTH_LEVEL_VERIFIED);
        }
    }

    /**
     * @see SimpleID\Auth\LoginEvent
     * @return void
     */
    public function onLoginEvent(LoginEvent $event) {
        $user = $event->getUser();
        $level = $event->getAuthLevel();
        $form_state = $event->getFormState();
        
        $auth = AuthManager::instance();
        $store = StoreManager::instance();

        if (($level >= AuthManager::AUTH_LEVEL_VERIFIED) && isset($form_state['otp_remember']) && ($form_state['otp_remember'] == 1)) {
            $uaid = $auth->assignUAID();
            $remember = $user['otp']['remember'];
            $remember[] = $uaid;
            $user->set('otp.remember', array_unique($remember));

            $store->saveUser($user);
        }
    }

    /**
     * Verifies a one time password (OTP) specified by the user.
     *
     * This function compares an OTP supplied by a user with the OTP
     * calculated based on the current time and the parameters of the
     * algorithm.  The parameters, such as the secret key, are supplied
     * using in $params.  These parameters are typically stored for each
     * user in the user store.
     *
     * To allow for clocks going out of sync, the current time will be
     * by a number (in time steps) specified in $params['drift'].  If
     * the OTP supplied by the user is accepted, $params['drift'] will
     * be also be updated with the latest difference.
     *
     * To allow for network delay, the function will accepts OTPs which
     * is a number of time steps away from the OTP calculated from the
     * adjusted time.  The maximum number of time steps is specified in
     * the $max_drift parameter.
     *
     * @param array<string, mixed> &$params the OTP parameters stored
     * @param string $code the OTP supplied by the user
     * @param int $max_drift the maximum drift allowed for network delay, in
     * time steps
     * @return bool whether the OTP supplied matches the OTP generated based on
     * the specified parameters, within the maximum drift
     */
    protected function verifyOTP(&$params, $code, $max_drift = 1) {
        $time = time();

        $test_code = $this->totp($params['secret'], $time, $params['period'], $params['drift'], $params['algorithm'], $params['digits']);
        
        if ($test_code == intval($code)) return true;

        for ($i = -$max_drift; $i <= $max_drift; $i++) {
            $test_code = $this->totp($params['secret'], $time, $params['period'], $params['drift'] + $i, $params['algorithm'], $params['digits']);
            if ($test_code == intval($code)) {
                $params['drift'] = $i;
                return true;
            }
        }
        return false;
        
    }

    /**
     * Calculates a Time-Based One-Time Password (TOTP) based on RFC 6238.
     *
     * This function returns an integer calculated from the TOTP algorithm.
     * The returned integer may need to be zero-padded to return a string
     * with the required number of digits
     *
     * @param string $secret the shared secret as a binary string
     * @param int $time the time to use in the HOTP algorithm.  If NULL, the
     * current time is used
     * @param int $period the time step in seconds
     * @param int $drift the number of time steps to be added to the time to
     * adjust for transmission delay
     * @param string $algorithm the hashing algorithm as supported by
     * the hash_hmac() function
     * @param int $digits the number of digits in the one-time password
     * @return int the one-time password
     * @link http://tools.ietf.org/html/rfc6238
     */
    public function totp($secret, $time = NULL, $period = 30, $drift = 0, $algorithm = 'sha1', $digits = 6) {
        if ($time == NULL) $time = time();
        $counter = floor($time / $period) + $drift;
        $data = pack('NN', 0, $counter);
        return $this->hotp($secret, $data, $algorithm, $digits);
    }

    /**
     * Calculates a HMAC-Based One-Time Password (HOTP) based on RFC 4226.
     *
     * This function returns an integer calculated from the HOTP algorithm.
     * The returned integer may need to be zero-padded to return a string
     * with the required number of digits
     *
     * @param string $secret the shared secret as a binary string
     * @param string $data the counter value as a 64 bit in
     * big endian encoding
     * @param string $algorithm the hashing algorithm as supported by
     * the hash_hmac() function
     * @param int $digits the number of digits in the one-time password
     * @return int the one-time password
     * @link http://tools.ietf.org/html/rfc4226
     */
    public function hotp($secret, $data, $algorithm = 'sha1', $digits = 6) {
        // unpack produces a 1-based array, we use array_merge to convert it to 0-based
        $unpacked = unpack('C*', hash_hmac(strtolower($algorithm), $data, $secret, true));
        assert($unpacked != false);
        $hmac = array_merge($unpacked);
        $offset = $hmac[19] & 0xf;
        $code = ($hmac[$offset + 0] & 0x7F) << 24 |
            ($hmac[$offset + 1] & 0xFF) << 16 |
            ($hmac[$offset + 2] & 0xFF) << 8 |
            ($hmac[$offset + 3] & 0xFF);
        return $code % pow(10, $digits);
    }

    /**
     * @return void
     */    
    public function onUserSecretDataPaths(BaseDataCollectionEvent $event) {
        $event->addResult([ 'otp.secret', 'otp.drift' ]);
    }
}
?>
