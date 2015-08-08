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
use SimpleID\Auth\AuthManager;
use SimpleID\Crypt\BigNum;
use SimpleID\Crypt\Random;
use SimpleID\Store\StoreManager;
use SimpleID\Util\SecurityToken;

/**
 * An authentication scheme module that provides two-factor authentication
 * based on a RFC 6238 Time-Based One-Time Password (TOTP).
 */
class OTPAuthSchemeModule extends AuthSchemeModule {

    static function routes($f3) {
        $f3->route('GET|POST /auth/otp', 'SimpleID\Auth\OTPAuthSchemeModule->setup');
    }

    /**
     * Displays the page used to set up login verification using one-time
     * passwords.
     */
    public function setup() {
        $auth = AuthManager::instance();
        $store = StoreManager::instance();
        $user = $auth->getUser();

        $tpl = new \Template();
        $token = new SecurityToken();

        // Require HTTPS, redirect if necessary
        $this->checkHttps('redirect', true);
    
        if (!$auth->isLoggedIn()) {
            $this->f3->reroute('/my/dashboard');
            return;
        }

        if ($this->f3->get('POST.op') == $this->t('Disable')) {
            if (($this->f3->exists('POST.tk') === false) || (!$token->verify($this->f3->get('POST.tk'), 'otp'))) {
                $this->f3->set('message', $this->t('SimpleID detected a potential security attack.  Please try again.'));
                $this->f3->mock('GET /my/dashboard');
                return;
            }

            if (isset($user['otp'])) {
                unset($user['otp']);
                $store->saveUser($user);
            }
            $this->f3->set('message', $this->t('Login verification has been disabled.'));
            $this->f3->mock('GET /my/dashboard');
            return;
        } elseif ($this->f3->get('POST.op') == $this->t('Verify')) {
            $params = $token->getPayload($this->f3->get('POST.otp_params'));
            $this->f3->set('otp_params', $this->f3->get('POST.otp_params'));

            if (($this->f3->exists('POST.tk') === false) || (!$token->verify($this->f3->get('POST.tk'), 'otp'))) {
                $this->f3->set('message', $this->t('SimpleID detected a potential security attack.  Please try again.'));
                page_dashboard();
                return;
            } elseif (($this->f3->exists('POST.otp') === false) || ($this->f3->get('POST.otp') == '')) {
                $this->f3->set('message', $this->t('You need to enter the verification code to complete enabling login verification.'));
            } elseif ($this->verifyOTP($params, $this->f3->get('POST.otp'), 10) === false) {
                $this->f3->set('message', $this->t('The verification code is not correct.'));
            } else {
                $user['otp'] = $params;
                $store->saveUser($user);

                $this->f3->set('message', $this->t('Login verification has been enabled.'));
                $this->f3->mock('GET /my/dashboard');
                return;
            }
        } else {
            $rand = new Random();

            $params = array(
                'type' => 'totp',
                'secret' => $rand->bytes(10),
                'algorithm' => 'sha1',
                'digits' => 6,
                'period' => 30,
                'drift' => 0,
                'remember' => array()
            );
            $this->f3->set('otp_params', $token->generate($params, SecurityToken::OPTION_BIND_SESSION));
        }

        $secret = new BigNum($params['secret'], 256);
        $code = strtr($secret->val(32), '0123456789abcdefghijklmnopqrstuv', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
        $code = str_repeat('A', 16 - strlen($code)) . $code;
        for ($i = 0; $i < strlen($code); $i += 4) {
            $this->f3->set('secret' . ($i + 1), substr($code, $i, 4));
        }

        $url = 'otpauth://totp/SimpleID?secret=' . $code . '&digits=' . $params['digits'] . '&period=' . $params['period'];
        $this->f3->set('qr', addslashes($url));

        $this->f3->set('about_otp', $this->t('Login verification adds an extra layer of protection to your account. When enabled, you will need to enter an additional security code whenever you log into SimpleID.'));
        $this->f3->set('otp_warning', $this->t('<strong>WARNING:</strong> If you enable login verification and lose your authenticator app, you will need to <a href="!url">edit your identity file manually</a> before you can log in again.',
            array('!url' => 'http://simpleid.koinic.net/docs/2/common_problems/#otp')
        ));

        $this->f3->set('setup_otp', $this->t('To set up login verification, following these steps.'));
        $this->f3->set('download_app', $this->t('Download an authenticator app that supports TOTP for your smartphone, such as Google Authenticator.'));
        $this->f3->set('add_account', $this->t('Add your SimpleID account to authenticator app using this key.  If you are viewing this page on your smartphone you can use <a href="!url">this link</a> or scan the QR code to add your account.',
            array('!url' => $url)
        ));
        $this->f3->set('verify_code', $this->t('To check that your account has been added properly, enter the verification code from your phone into the box below, and click Verify.'));
        
        $this->f3->set('tk', $token->generate('otp', SecurityToken::OPTION_BIND_SESSION));
        $this->f3->set('otp_label', $this->t('Verification code:'));
        $this->f3->set('submit_button', $this->t('Verify'));

        $this->f3->set('page_class', 'dialog-page');
        $this->f3->set('title', $this->t('Login Verification'));

        $this->f3->set('framekiller', true);
        
        $this->f3->set('layout', 'auth_otp_setup.html');
        print $tpl->render('page.html');
    }

    /**
     * Returns the dashboard OTP block.
     *
     * @return array the dashboard OTP block
     */
    public function dashboardBlocksHook() {
        $auth = AuthManager::instance();
        $user = $auth->getUser();

        $base_path = $this->f3->get('base_path');

        $token = new SecurityToken();
        $tk = $token->generate('otp', SecurityToken::OPTION_BIND_SESSION);

        $html = '<p>' . $this->t('Login verification adds an extra layer of protection to your account. When enabled, you will need to enter an additional security code whenever you log into SimpleID.') . '</p>';

        if (isset($user['otp'])) {
            $html .= '<p>' . $this->t('Login verification is <strong>enabled</strong>.') . '</p>';
            $html .= '<form action="' . $base_path . 'auth/otp" method="post" enctype="application/x-www-form-urlencoded"><input type="hidden" name="tk" value="'. $tk . '"/>';
            $html .= '<input type="submit" name="op" value="' . $this->t('Disable') . '" /></form>';
        } else {
            $html .= '<p>' . $this->t('Login verification is <strong>disabled</strong>. To enable login verification, click the button below.') . '</p>';
            $html .= '<form action="' . $base_path . 'auth/otp" method="post" enctype="application/x-www-form-urlencoded"><input type="hidden" name="tk" value="'. $tk . '"/>';
            $html .= '<input type="submit" name="op" value="' . $this->t('Enable') . '" /></form>';
        }
        
        return array(array(
            'id' => 'otp',
            'title' => $this->t('Login Verification'),
            'content' => $html,
            'weight' => 0
        ));
    }

    /**
     * @see SimpleID\API\AuthHooks::loginFormHook()
     */
    public function loginFormHook(&$form_state) {
        if ($form_state['mode'] == AuthManager::MODE_VERIFY) {
            $auth = AuthManager::instance();
            $store = StoreManager::instance();

            $test_user = $store->loadUser($form_state['uid']);
            if (!isset($test_user['otp'])) return;
            if ($test_user['otp']['type'] == 'recovery') return;

            $uaid = $auth->assignUAID();
            if (isset($user->auth[$uaid]) && isset($user->auth[$uaid]['otp']) && $user->auth[$uaid]['otp']['remember']) return;

            $tpl = new \Template();

            // Note this is called from user_login(), so $_POST is always filled
            $this->f3->set('otp_instructions_label', $this->t('To verify your identity, enter the verification code.'));
            $this->f3->set('otp_recovery_label', $this->t('If you have lost your verification code, you can <a href="!url">recover your account</a>.',
                array('!url' => 'http://simpleid.koinic.net/docs/2/common_problems/#otp')
            ));
            $this->f3->set('otp_remember_label', $this->t('Do not ask for verification codes again on this browser.'));

            $this->f3->set('otp_label', $this->t('Verification code:'));
            
            $this->f3->set('submit_button', $this->t('Verify'));
            
            return array(
                array(
                    'content' => $tpl->render('auth_otp.html', false),
                    'weight' => 0
                )
            );
        }
    }

    /**
     * @see SimpleID\API\AuthHooks::loginFormValidateHook()
     */
    public function loginFormValidateHook(&$form_state) {
        if ($form_state['mode'] == AuthManager::MODE_VERIFY) {
            if ($this->f3->exists('POST.otp.otp') === false) {
                $this->f3->set('message', $this->t('You need to enter the verification code in order to log in.'));
                return false;
            }
            return true;
        }
    }

    /**
     * @see SimpleID\API\AuthHooks::loginFormSubmitHook()
     */
    public function loginFormSubmitHook(&$form_state) {
        if ($form_state['mode'] == AuthManager::MODE_VERIFY) {
            $store = StoreManager::instance();

            $uid = $form_state['uid'];
            $test_user = $store->loadUser($form_state['uid']);
            $params = $test_user['otp'];
            
            if ($this->verifyOTP($params, $this->f3->get('POST.otp.otp'), 10) === false) {
                $this->f3->set('message', $this->t('The verification code is not correct.'));
                return false;
            }

            if ($this->f3->get('POST.otp.remember') == '1') $form_state['otp_remember'] = 1;

            $test_user['otp'] = $params;
            $store->saveUser($test_user); // Save the drift

            return array('auth_level' => $form_state['mode']);
        }
    }

    /**
     * @see SimpleID\API\AuthHooks::loginHook()
     */
    public function loginHook($user, $level, $modules, $form_state) {
        $auth = AuthManager::instance();
        $store = StoreManager::instance();

        if (($level >= AuthManager::AUTH_LEVEL_VERIFIED) && isset($form_state['otp_remember']) && ($form_state['otp_remember'] == 1)) {
            $uaid = $auth->assignUAID();

            if (!isset($user->auth[$uaid])) $user->auth[$uaid] = array();
            if (!isset($user->auth[$uaid]['otp'])) $user->auth[$uaid]['otp'] = array();
            
            $user->auth[$uaid]['otp']['remember'] = true;

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
     * @param array &$params the OTP parameters stored
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
        $hmac = array_merge(unpack('C*', hash_hmac(strtolower($algorithm), $data, $secret, true)));
        $offset = $hmac[19] & 0xf;
        $code = ($hmac[$offset + 0] & 0x7F) << 24 |
            ($hmac[$offset + 1] & 0xFF) << 16 |
            ($hmac[$offset + 2] & 0xFF) << 8 |
            ($hmac[$offset + 3] & 0xFF);
        return $code % pow(10, $digits);
    }

    /**
     * @see SimpleID\API\AuthHooks::secretUserDataPathsHook()
     */
    public function secretUserDataPathsHook() {
        return array('otp.secret', 'otp.drift');
    }
}
?>