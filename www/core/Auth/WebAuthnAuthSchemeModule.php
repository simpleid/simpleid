<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2024-2025
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
use SimpleID\Crypt\Random;
use SimpleID\Crypt\SecurityToken;
use SimpleID\Models\User;
use SimpleID\Store\StoreManager;
use SimpleID\Util\Events\UIBuildEvent;
use SimpleID\Util\Forms\FormBuildEvent;
use SimpleID\Util\Forms\FormSubmitEvent;
use SimpleID\Util\UI\Template;
use SimpleJWT\Crypt\AlgorithmFactory;
use SimpleJWT\Keys\KeyFactory;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Util\Util as SimpleJWTUtil;

/**
 * An authentication scheme module that uses security keys with WebAuthn.
 * 
 * Currently this scheme only supports two-factor authentication.
 */
class WebAuthnAuthSchemeModule extends AuthSchemeModule {
    /** @var array<int, string> */
    static $cose_alg_map = [
        -257 => 'RS256',
        -7 => 'ES256'
    ];

    static function init($f3) {
        $f3->route('GET|POST /auth/webauthn', 'SimpleID\Auth\WebAuthnAuthSchemeModule->setup');
        $f3->route('POST @webauthn_challenge: /auth/webauthn/challenge [ajax]', 'SimpleID\Auth\WebAuthnAuthSchemeModule->createChallenge');
        $f3->route('GET /auth/webauthn/credentials [ajax]', 'SimpleID\Auth\WebAuthnAuthSchemeModule->listCredentials');
        $f3->map('/auth/webauthn/credentials/@id', 'SimpleID\Auth\WebAuthnAuthSchemeModule');
    }

    /**
     * API endpoint to create a random challenge that can be verified
     * using this module.
     * 
     * @return void
     */
    public function createChallenge() {
        $this->checkHttps('error', true);

        $token = new SecurityToken();
        if (!$this->f3->exists('HEADERS.X-Request-Token') || !$token->verify($this->f3->get('HEADERS.X-Request-Token'), 'webauthn')) {
            $this->f3->status(401);
            print json_encode([
                'error' => 'unauthorized',
                'error_description' => $this->f3->get('intl.common.unauthorized')
            ]);
            return;
        }

        $rand = new Random();
        $challenge = SimpleJWTUtil::base64url_encode($rand->bytes(32));

        // Wrap the challenge in a SecurityToken to ensure it is only used once
        $nonce = $token->generate($challenge, SecurityToken::OPTION_NONCE);
        
        header('Content-Type: application/json');

        print json_encode([
            'challenge' => $challenge,
            'nonce' => $nonce,
            'expires_in' => SIMPLEID_HUMAN_TOKEN_EXPIRES_IN,
        ]);
    }

    /**
     * API endpoint to list the saved credentials for the current logged-in
     * user.
     * 
     * @return void
     */
    public function listCredentials() {
        $this->checkHttps('error', true);

        header('Content-Type: application/json');

        $token = new SecurityToken();
        if (!$this->f3->exists('HEADERS.X-Request-Token') || !$token->verify($this->f3->get('HEADERS.X-Request-Token'), 'webauthn')) {
            $this->f3->status(401);
            print json_encode([
                'error' => 'unauthorized',
                'error_description' => $this->f3->get('intl.common.unauthorized')
            ]);
            return;
        }

        $auth = AuthManager::instance();
        $user = $auth->getUser();
        $results = $this->getSavedCredentials($user, true);

        print json_encode($results);
    }

    /**
     * API endpoint to delete a stored credential
     * 
     * @param \Base $f3
     * @param array<string, mixed> $params
     * @return void
     */
    public function delete($f3, $params) {
        $this->checkHttps('error', true);
        parse_str($this->f3->get('BODY'), $delete);

        header('Content-Type: application/json');

        $token = new SecurityToken();
        if (!$this->f3->exists('HEADERS.X-Request-Token') || !$token->verify($this->f3->get('HEADERS.X-Request-Token'), 'webauthn')) {
            $this->f3->status(401);
            print json_encode([
                'error' => 'unauthorized',
                'error_description' => $this->f3->get('intl.common.unauthorized'),
            ]);
            return;
        }

        $auth = AuthManager::instance();
        $user = $auth->getUser();

        // $params['id'] is escaped using brackets
        if (!$user->exists('webauthn.credentials.[' . $params['id'] . ']')) {
            $this->f3->status(404);
            print json_encode([
                'error' => 'not_found',
                'error_description' => $this->f3->get('intl.common.not_found')
            ]);
            return;
        }

        $user->unset('webauthn.credentials.[' . $params['id'] . ']');

        $event = new CredentialEvent($user, CredentialEvent::CREDENTIAL_DELETED_EVENT, self::class, $params['id']);
        \Events::instance()->dispatch($event);

        
        $store = StoreManager::instance();
        $store->saveUser($user);

        print json_encode([
            'result' => 'success',
            'result_description' => $this->f3->get('intl.core.auth_webauthn.credential_delete_success')
        ]);
    }

    /**
     * Displays the page to add a WebAuthn credential.
     * 
     * @return void
     */
    public function setup() {
        $auth = AuthManager::instance();
        $store = StoreManager::instance();
        /** @var User $user */
        $user = $auth->getUser();

        $tpl = Template::instance();
        $token = new SecurityToken();

        // Require HTTPS, redirect if necessary
        $this->checkHttps('redirect', true);
    
        if (!$auth->isLoggedIn()) {
            $this->f3->reroute('/my/dashboard');
            return;
        }

        if ($this->f3->exists('POST.result')) {
            if (($this->f3->exists('POST.tk') === false) || (!$token->verify($this->f3->get('POST.tk'), 'webauthn'))) {
                $this->f3->set('message', $this->f3->get('intl.common.invalid_tk'));
                $this->f3->mock('GET /my/dashboard');
                return;
            }

            $credential = $this->processNewCredential($this->f3->get('POST.challenge'), $this->f3->get('POST.nonce'), $this->f3->get('POST.result'), $this->f3->get('POST.name'));

            if ($credential == null) {
                $this->f3->set('message', $this->f3->get('intl.core.auth_webauthn.credential_add_error'));
            } else {
                $user->set('webauthn.credentials.' . $credential['id'], $credential);
                $store->saveUser($user);

                $event = new CredentialEvent($user, CredentialEvent::CREDENTIAL_ADDED_EVENT, self::class, $credential['id']);
                \Events::instance()->dispatch($event);

                $this->f3->set('message', $this->f3->get('intl.core.auth_webauthn.credential_add_success'));
                $this->f3->mock('GET /my/dashboard');
                return;
            }
        }

        $this->f3->set('challenge_url', $this->getCanonicalURL('@webauthn_challenge', '', 'https'));

        $rp_name = ($this->f3->exists('config.site_title')) ? $this->f3->get('config.site_title') : 'SimpleID';
        $options = [
            'rp' => [
                'id' => $this->getRpId(),
                'name' => $rp_name
            ],
            'user' => [
                'id' => SimpleJWTUtil::base64url_encode($user->getPairwiseIdentity('webauthn')),
                'name' => ($user->exists('userinfo.nickname')) ? $user->get('userinfo.nickname') : $user['uid'],
                'displayName' => $user->getDisplayName()
            ],
            'pubKeyCredParams' => array_map(function ($n) { return [ 'alg' => $n, 'type' => 'public-key' ]; }, array_keys(self::$cose_alg_map)),
            'hints' => [ 'security-key', 'client-device' ],
            // For passkeys, authenticatorAttachment='platform'
            'authenticatorSelection' => [
                'residentKey' => 'discouraged',
                'userVerification' => 'preferred'
            ],
            'timeout' => SIMPLEID_HUMAN_TOKEN_EXPIRES_IN,
            'attestation' => 'none',
        ];
        if (isset($user['webauthn']['credentials']))
            $options['excludeCredentials'] = $this->getSavedCredentials($user);

        $this->f3->set('create_options', $options);

        $this->f3->set('otp_recovery_url', 'https://simpleid.org/docs/2/common-problems/#otp');

        $this->f3->set('js_data.intl.challenge_error',  $this->f3->get('intl.core.auth_webauthn.challenge_error'));
        $this->f3->set('js_data.intl.browser_error',  $this->f3->get('intl.core.auth_webauthn.browser_error'));
        
        $this->f3->set('tk', $token->generate('webauthn', SecurityToken::OPTION_BIND_SESSION));

        $this->f3->set('page_class', 'is-dialog-page');
        $this->f3->set('title', $this->f3->get('intl.core.auth_webauthn.webauthn_title'));
        $this->f3->set('layout', 'auth_webauthn_setup.html');

        header('X-Frame-Options: DENY');
        print $tpl->render('page.html');
    }

    /**
     * Returns the dashboard block.
     *
     * @param UIBuildEvent $event the event to collect
     * the dashboard block
     * @return void
     */
    public function onDashboardBlocks(UIBuildEvent $event) {
        $tpl = Template::instance();

        $auth = AuthManager::instance();
        $user = $auth->getUser();

        $base_path = $this->f3->get('base_path');

        $token = new SecurityToken();
        $this->f3->set('webauthn_tk', $token->generate('webauthn', SecurityToken::OPTION_BIND_SESSION));

        $this->f3->set('js_data.intl.credential_confirm_delete',  $this->f3->get('intl.core.auth_webauthn.credential_confirm_delete'));

        $event->addBlock('webauthn', $tpl->render('auth_webauthn_dashboard.html', false), 0, [
            'title' => $this->f3->get('intl.core.auth_webauthn.webauthn_title')
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
            if (!isset($test_user['webauthn'])) return;
            /*if ($test_user['otp']['type'] == 'recovery') return;*/

            $uaid = $auth->assignUAID();
            if ($test_user->exists('webauthn.remember') && in_array($uaid, $test_user->get('webauthn.remember'))) return;

            $tpl = Template::instance();
            $token = new SecurityToken();

            $this->f3->set('challenge_url', $this->getCanonicalURL('@webauthn_challenge', '', 'https'));
            $this->f3->set('challenge_tk', $token->generate('webauthn', SecurityToken::OPTION_BIND_SESSION));

            $options = [
                'mediation' => 'required',
                'publicKey' => [
                    'userVerification' => 'required',
                    'timeout' => 30000,
                    'rpId' => $this->getRpId(),
                    'allowCredentials' => $this->getSavedCredentials($test_user)
                ]
            ];
            $this->f3->set('request_options', $options);

            // Note this is called from user_login(), so $_POST is always filled
            $this->f3->set('otp_recovery_url', 'https://simpleid.org/docs/2/common_problems/#otp');

            $this->f3->set('js_data.intl.challenge_error',  $this->f3->get('intl.core.auth_webauthn.challenge_error'));
            $this->f3->set('js_data.intl.browser_error',  $this->f3->get('intl.core.auth_webauthn.browser_error'));

            $event->addBlock('auth_webauthn', $tpl->render('auth_webauthn.html', false), 0, [ 'showSubmitButton' => false]);
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
            $test_credentials = $test_user->get('webauthn.credentials');

            $result = $this->verifyCredential($this->f3->get('POST.webauthn.challenge'), $this->f3->get('POST.webauthn.nonce'), $test_credentials, $this->f3->get('POST.webauthn.result'));
            
            if ($result === false) {
                $event->addMessage($this->f3->get('intl.core.auth_webauthn.credential_verify_error'));
                $event->setInvalid();
                return;
            }

            if ($this->f3->get('POST.webauthn.remember') == '1') $form_state['webauthn_remember'] = 1;

            // Update activity.sign_count, activity.last_time
            $prefix = 'webauthn.credentials.[' . $result['credential_id'] . ']';
            $test_user->set($prefix . '.activity.last_time', (new \DateTimeImmutable())->getTimestamp());
            $test_user->set($prefix . '.activity.sign_count', $result['sign_count']);
            $store->saveUser($test_user);

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

        if (($level >= AuthManager::AUTH_LEVEL_VERIFIED) && isset($form_state['webauthn_remember']) && ($form_state['webauthn_remember'] == 1)) {
            $uaid = $auth->assignUAID();
            $remember = $user['webauthn']['remember'];
            $remember[] = $uaid;
            $user->set('webauthn.remember', array_unique($remember));

            $store->saveUser($user);
        }
    }

    /**
     * @return void
     */
    public function onLogoutEvent(LogoutEvent $event) {
        // If signed in using passwordless, call window.credentials.preventSilentAccess()
    }

    /**
     * Processes a new WebAuthn credential.  The new credential is represented
     * by PublicKeyCredential object (with AuthenticatorAttestationResponse).
     * 
     * This method checks that the credential creation response is valid and, if so, provides
     * a result array which can be saved in the user's profile.
     * 
     * Note that this method does not perform detailed checks on the
     * attestation data.
     * 
     * @param string $challenge the expected challenge value
     * @param string $nonce the expected nonce value provided by the {@link #createChallenge()}
     * method
     * @param string $new_credential_json the credential creation response
     * as a JSON string (with Uint8Array and Buffer values encoded as base64url)
     * @param ?string $display_name the name of the credential chosen
     * by the user
     * @return array<string, mixed>|null an array representing the credential
     * to be used in the user's profile, or null if the credential creation response
     * is not valid
     */
    protected function processNewCredential(string $challenge, string $nonce, string $new_credential_json, string $display_name = null): ?array {
        // 1. Check that nonce = challenge
        $token = new SecurityToken();
        if (!$token->verify($nonce, $challenge)) {
            return null;
        }

        // 2. Decode WebAuthn credential creation response
        $new_credential = json_decode($new_credential_json, true);

        // 3. Check client data
        $client_data = json_decode(SimpleJWTUtil::base64url_decode($new_credential['response']['clientDataJSON']), true);

        if ($client_data['type'] != 'webauthn.create') {
            $this->logger->log(LogLevel::ERROR, 'Invalid client type: expected webauthn.create, got ' . $client_data['type']);
            return null;
        }

        if ($client_data['origin'] != $this->getOrigin($this->f3->get('config.canonical_base_path'))) {
            $this->logger->log(LogLevel::ERROR, 'Invalid client origin: ' . $client_data['origin']);
            return null;
        }

        if (!$this->secureCompare($client_data['challenge'], $challenge)) {
            $this->logger->log(LogLevel::ERROR, 'Challenge value does not match: expected ' . $challenge . ', got ' . $client_data['challenge']);
            return null;
        }
    
        // 4. Check authenticator data
        $authenticator = new WebAuthnAuthenticatorData(SimpleJWTUtil::base64url_decode($new_credential['response']['authenticatorData']));
        $aaguid = $authenticator->getAAGUID();

        if ($aaguid != null) {
            // Get authenticator info.
            // Note that without additional browser permission, the aaugid will be empty
        }

        // 5. Convert public key from base64url encoded DER to JWK
        //    (by converting it to PEM first)
        $pem = wordwrap("-----BEGIN PUBLIC KEY-----\n" . strtr($new_credential['response']['publicKey'], '-_', '+/') . "\n-----END PUBLIC KEY-----\n", 64, "\n", true);
        $key = KeyFactory::create($pem, 'pem');

        // 6. Display name
        $time = new \DateTimeImmutable();
        if ($display_name == null) $display_name = $time->format(\DateTimeImmutable::ISO8601);

        // 7. Return result
        $result = [
            'id' => $new_credential['id'],
            'type' => $new_credential['type'],

            'display_name' => $display_name,
            'use' => 'verify',
            'authenticator' => [
                'aaguid' => $aaguid,
                'user_verified' => $authenticator->isUserVerified(),
                'backup_eligible' => $authenticator->isBackupEligible()
            ],
            'public_key' => [
                'jwk' => $key->getKeyData(),
                'alg' => self::$cose_alg_map[$new_credential['response']['publicKeyAlgorithm']],
                'transports' => $new_credential['response']['transports']
            ],
            'activity' => [
                'first_time' => $time->getTimestamp(),
                'last_time' => $time->getTimestamp(),
                'backed_up' => $authenticator->isBackedUp(),
                'sign_count' => $authenticator->getSignCount()
            ]
        ];

        return $result;
    }

    /**
     * Verifies a WebAuthn credential supplied by the browser against credentials that are
     * stored for a user.  The supplied credential is represented
     * by PublicKeyCredential object (with AuthenticatorAssertionResponse).
     * 
     * This method checks that the credential response is valid and, if so, provides
     * a result array which can be used to update the user's profile.
     * 
     * Note that this method does not perform detailed checks on the
     * assertion data.
     * 
     * @param string $challenge the expected challenge value
     * @param string $nonce the expected nonce value provided by the {@link #createChallenge()}
     * method
     * @param array<string, mixed> $stored_credentials an associative array of
     * credentials stored in the user's profile
     * @param string $credential_json the credential response
     * as a JSON string (with Uint8Array and Buffer values encoded as base64url)
     * @return array<string, mixed>|false an array representing the verification result,
     * or false if the credential response is not valid
     */
    protected function verifyCredential(string $challenge, string $nonce, array $stored_credentials, string $credential_json) {
        // 1. Check that nonce = challenge
        $token = new SecurityToken();
        if (!$token->verify($nonce, $challenge)) {
            return false;
        }

        // 2. Decode WebAuthn credential response
        $credential = json_decode($credential_json, true);

        // 3. Check if the credential ID has been stored
        if (!array_key_exists($credential['id'], $stored_credentials)) {
            return false;
        }

        $test_credential = $stored_credentials[$credential['id']];

        // 4. Verify signature
        $client_data_json = SimpleJWTUtil::base64url_decode($credential['response']['clientDataJSON']);
        $authenticator_data = SimpleJWTUtil::base64url_decode($credential['response']['authenticatorData']);
        if (!$this->verifySignature($credential['response']['signature'], $authenticator_data, $client_data_json, $test_credential['public_key'])) {
            return false;
        }

        // 5. Check client data
        $client_data = json_decode($client_data_json, true);

        if ($client_data['type'] != 'webauthn.get') {
            $this->logger->log(LogLevel::ERROR, 'Invalid client type: expected webauthn.get, got ' . $client_data['type']);
            return false;
        }

        if ($client_data['origin'] != $this->getOrigin($this->f3->get('config.canonical_base_path'))) {
            $this->logger->log(LogLevel::ERROR, 'Invalid client origin: ' . $client_data['origin']);
            return false;
        }

        if (!$this->secureCompare($client_data['challenge'], $challenge)) {
            $this->logger->log(LogLevel::ERROR, 'Challenge value does not match: expected ' . $challenge . ', got ' . $client_data['challenge']);
            return false;
        }

        // 6. Check authenticator data
        $authenticator = new WebAuthnAuthenticatorData($authenticator_data);

        $rpIdHash = SimpleJWTUtil::base64url_encode(hash('sha256', $this->getRpId(), true));
        if (!$this->secureCompare($authenticator->getRpIdHash(), $rpIdHash)) {
            $this->logger->log(LogLevel::ERROR, 'RP ID hash does not match: expected ' . $rpIdHash . ', got ' . $authenticator->getRpIdHash());
            return false;
        }

        if (!$authenticator->isUserPresent()) {
            $this->logger->log(LogLevel::ERROR, 'User present flag not set in authenticatorData');
            return false;
        }

        // If the user was verified when the credential was added, then the user
        // must be verified on each use
        if ($test_credential['authenticator']['user_verified'] && !$authenticator->isUserVerified()) {
            $this->logger->log(LogLevel::ERROR, 'User verified flag not set in authenticatorData when flag it was set on creation');
            return false;
        }

        $test_sign_count = $test_credential['activity']['sign_count'];
        if (($test_sign_count > 0) && ($authenticator->getSignCount() <= $test_sign_count)) {
            $this->logger->log(LogLevel::ERROR, 'Sign count too low: expected >' . $test_sign_count . ', got ' . $authenticator->getSignCount());
            return false;
        }

        // 7. Return result
        return [
            'credential_id' => $credential['id'],
            'user_ppid' => $credential['response']['userHandle'],
            'user_verified' => $authenticator->isUserVerified(),
            'backed_up' => $authenticator->isBackedUp(),
            'sign_count' => $authenticator->getSignCount()
        ];
    }

    /**
     * Verifies the WebAuthn signature.
     * 
     * @param string $signature the base64url encoded signature to verify
     * @param string $authenticator_data the authenticatorData provided by the browser
     * as a binary string
     * @param string $client_data_json the clientDataJSON provided by the browser
     * as a JSON string
     * @param array<string, mixed> $test_public_key the `public_key` value from the
     * stored credentials
     * @return bool true if the signature is valid
     */
    protected function verifySignature(string $signature, string $authenticator_data, string $client_data_json, array $test_public_key): bool {
        $signing_input = $authenticator_data . hash('sha256', $client_data_json, true);

        $set = new KeySet();
        $key = KeyFactory::create($test_public_key['jwk'], 'php');
        $set->add($key);

        if ($key->getKeyType() == \SimpleJWT\Keys\ECKey::KTY) {
            // Under the WebAuthn specification, $signature for ECDSA-based algorithms
            // is encoded as a ASN.1 DER SEQUENCE.  However, SimpleJWT expects
            // this signature to be the raw integers (r, s) concatenated.  Therefore
            // we need to convert the signature into the required format
            $binary = SimpleJWTUtil::base64url_decode($signature);

            $der = new \SimpleJWT\Util\ASN1\DER();
            $seq = $der->decode($binary);
            $r = $seq->getChildAt(0)->getValueAsUIntOctets();
            $s = $seq->getChildAt(1)->getValueAsUIntOctets();

            // Now pad out r and s so that they are $key->getSize() bits long
            $r = str_pad($r, $key->getSize() / 8, "\x00", STR_PAD_LEFT);
            $s = str_pad($s, $key->getSize() / 8, "\x00", STR_PAD_LEFT);

            $signature = SimpleJWTUtil::base64url_encode($r . $s);
        }

        /** @var \SimpleJWT\Crypt\Signature\SignatureAlgorithm $alg */
        $alg = AlgorithmFactory::create($test_public_key['alg']);
        return $alg->verify($signature, $signing_input, $set);
    }

    /**
     * Returns the RP ID for this installation.
     * 
     * The RP ID is generated from the `canonical_base_path` variable.
     * 
     * @return string the RP ID
     */
    protected function getRpId(): string {
        /** @var string $rpId */
        $rpId = parse_url($this->f3->get('config.canonical_base_path'), PHP_URL_HOST);
        return $rpId;
    }

    /**
     * Retrieves saved credentials for a specified user.
     * 
     * The `$include_details` parameter can be set to determine whether
     * additional details (such as the display name and usage information) are
     * returned.  When using the Credentials browser API, `$include_details`
     * should be set to false.
     * 
     * @param User $user the user
     * @param bool $include_details whether additional details are included in the result
     * @return array<array<string, mixed>> the credentials
     */
    protected function getSavedCredentials(User $user, bool $include_details = false): array {
        if (!$user->exists('webauthn.credentials') || (count($user->get('webauthn.credentials')) == 0))
            return [];

        return array_map(function($credential) use ($include_details) {
            $result = [
                'id' => $credential['id'],
                'type' => $credential['type']
            ];
            if ($include_details) {
                $result['display_name'] = $credential['display_name'];
                $result['use'] = $credential['use'];
                $result['authenticator'] = $credential['authenticator'];
                $result['activity'] = $credential['activity'];
            }
            return $result;
        }, array_values($user->get('webauthn.credentials')));
    }
}
?>
