<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2023
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

namespace SimpleID\Protocols\OpenID;

use Psr\Log\LogLevel;
use SimpleID\Module;
use SimpleID\ModuleManager;
use SimpleID\Base\IndexEvent;
use SimpleID\Base\ScopeInfoCollectionEvent;
use SimpleID\Auth\AuthManager;
use SimpleID\Crypt\Random;
use SimpleID\Protocols\ProtocolResult;
use SimpleID\Store\StoreManager;
use SimpleID\Util\SecurityToken;
use SimpleID\Util\Events\BaseDataCollectionEvent;
use SimpleID\Util\Events\UIBuildEvent;
use SimpleID\Util\Forms\FormBuildEvent;
use SimpleID\Util\Forms\FormSubmitEvent;
use SimpleID\Util\Forms\FormState;

/**
 * The module for authentication under OpenID version 1.1 and 2.0
 */
class OpenIDModule extends Module implements ProtocolResult {

    /** Constant for the XRDS service type for return_to verification */
    const OPENID_RETURN_TO = 'http://specs.openid.net/auth/2.0/return_to';

    const DEFAULT_SCOPE = 'tag:simpleid.sf.net,2021:openid:default';

    /** @var \Cache */
    protected $cache;

    /** @var ModuleManager */
    protected $mgr;

    static function init($f3) {
        $f3->route('GET @openid_provider_xrds: /openid/xrds', 'SimpleID\Protocols\OpenID\OpenIDModule->providerXRDS');
        $f3->route('GET @openid_user_xrds: /user/@uid/xrds', 'SimpleID\Protocols\OpenID\OpenIDModule->userXRDS');
        $f3->route('POST @openid_consent: /openid/consent', 'SimpleID\Protocols\OpenID\OpenIDModule->consent');
    }

    function __construct() {
        parent::__construct();
        $this->cache = \Cache::instance();
        $this->mgr = ModuleManager::instance();
    }

    /**
     * @return void
     */
    public function onIndexEvent(IndexEvent $event) {
        $_request = $event->getRequest();

        $web = \Web::instance();
        $content_type = $web->acceptable([ 'text/html', 'application/xml', 'application/xhtml+xml', 'application/xrds+xml' ]);

        if (isset($_request['openid.mode'])) {
            $this->start(new Request($_request));
            $event->stopPropagation();
        } elseif ($content_type == 'application/xrds+xml') {
            $this->providerXRDS();
            $event->stopPropagation();
        } else {
            // Point to SimpleID's XRDS document
            header('X-XRDS-Location: ' . $this->getCanonicalURL('@openid_provider_xrds'));
            return;
        }
    }

    /**
     * Process an OpenID request under versions 1 and 2.
     *
     * This function determines the version of the OpenID specification that is
     * relevant to this request, checks openid.mode and passes the
     * request on to the function required to process the request.
     *
     * The OpenID request expressed as an array contain key-value pairs corresponding
     * to the HTTP request.  This is usually contained in the <code>$_REQUEST</code>
     * variable.
     *
     * @param Request $request the OpenID request
     * @return void
     */
    public function start($request) {
        switch ($request['openid.mode']) {
            case 'associate':
                $this->associate($request);
                break;
            case 'checkid_immediate':
            case 'checkid_setup':
                $token = new SecurityToken();
                $state = [ 'rq' => $request->toArray() ];
                $this->checkHttps('redirect', true, $this->getCanonicalURL('continue/' . rawurlencode($token->generate($state)), '', 'https'));
                
                $this->checkid($request);
                break;
            case 'check_authentication':
                $this->check_authentication($request);
                break;
            default:
                if (isset($request['openid.return_to'])) {
                    // Indirect communication - send error via indirect communication.
                    $this->fatalError($this->f3->get('intl.core.openid.invalid_message'));
                } else {
                    // Direct communication
                    $this->directError('Invalid OpenID message.', [], $request);
                }
        }
    }

    /**
     * Processes an association request from a relying party under OpenID versions
     * 1 and 2.
     *
     * An association request has an openid.mode value of
     * associate.  This function checks whether the association request
     * is valid, and if so, creates an association and sends the response to
     * the relying party.
     *
     * @param Request $request the OpenID request
     * @return void
     * @link http://openid.net/specs/openid-authentication-1_1.html#mode_associate, http://openid.net/specs/openid-authentication-2_0.html#associations
     */
    protected function associate($request) {
        $this->logger->log(LogLevel::DEBUG, 'SimpleID\Protocols\OpenID\OpenIDModule->associate');
        $this->logger->log(LogLevel::INFO, 'OpenID association request', $request->toArray());
        
        $assoc_types = Association::getAssociationTypes();
        $session_types = Association::getSessionTypes($this->isHttps(), $request->getVersion());

        // Common Request Parameters [8.1.1]
        if (($request->getVersion() == Message::OPENID_VERSION_1_1) && !isset($request['openid.session_type'])) $request['openid.session_type'] = '';
        $assoc_type = $request['openid.assoc_type'];
        $session_type = $request['openid.session_type'];
        
        // Diffie-Hellman Request Parameters [8.1.2]
        $dh_modulus = (isset($request['openid.dh_modulus'])) ? $request['openid.dh_modulus'] : NULL;
        $dh_gen = (isset($request['openid.dh_gen'])) ? $request['openid.dh_gen'] : NULL;
        $dh_consumer_public = $request['openid.dh_consumer_public'];
        
        if (!isset($request['openid.session_type']) || !isset($request['openid.assoc_type'])) {
            $this->logger->log(LogLevel::ERROR, 'Association failed: openid.session_type or openid.assoc_type not set');
            $this->directError('openid.session_type or openid.assoc_type not set', [], $request);
            return;
        }
        
        // Check if the assoc_type is supported
        if (!array_key_exists($assoc_type, $assoc_types)) {
            $error = [
                'error_code' => 'unsupported-type',
                'session_type' => 'DH-SHA1',
                'assoc_type' => 'HMAC-SHA1'
            ];
            $this->logger->log(LogLevel::ERROR, 'Association failed: The association type is not supported by SimpleID.');
            $this->directError('The association type is not supported by SimpleID.', $error, $request);
            return;
        }
        // Check if the session_type is supported
        if (!array_key_exists($session_type, $session_types)) {
            $error = [
                'error_code' => 'unsupported-type',
                'session_type' => 'DH-SHA1',
                'assoc_type' => 'HMAC-SHA1'
            ];
            $this->logger->log(LogLevel::ERROR, 'Association failed: The session type is not supported by SimpleID.');
            $this->directError('The session type is not supported by SimpleID.', $error, $request);
            return;
        }
        
        if ($session_type == 'DH-SHA1' || $session_type == 'DH-SHA256') {
            if (!$dh_consumer_public) {
                $this->logger->log(LogLevel::ERROR, 'Association failed: openid.dh_consumer_public not set');
                $this->directError('openid.dh_consumer_public not set', [], $request);
                return;
            }
        }

        $association = new Association(Association::ASSOCIATION_SHARED, $assoc_type);
        $this->logger->log(LogLevel::INFO, 'Created association: ' . $association->toString());

        $this->cache->set($association->getHandle() . '.openid_association', $association, SIMPLEID_SHORT_TOKEN_EXPIRES_IN);

        $response = new Response($request);
        $response->setArray($association->getOpenIDResponse($session_type, $dh_consumer_public, $dh_modulus, $dh_gen));
        $response->set('expires_in', strval(SIMPLEID_SHORT_TOKEN_EXPIRES_IN));
        $this->logger->log(LogLevel::INFO, 'Association response', $response->toArray());

        $response->render();
    }

    /**
     * Processes an authentication request from a relying party.
     *
     * An authentication request has an openid.mode value of
     * checkid_setup or checkid_immediate.
     *
     * If the authentication request is a standard OpenID request about an identity
     * (i.e. contains the key openid.identity), this function calls
     * {@link simpleid_checkid_identity()} to see whether the user logged on into SimpleID
     * matches the identity supplied in the OpenID request.
     *
     * If the authentication request is not about an identity, this function calls
     * the {@link hook_checkid() checkid hook} of the loaded extensions.
     *
     * Depending on the OpenID version, this function will supply an appropriate
     * assertion.
     *
     * @param Request $request the OpenID request
     * @return void
     */
    public function checkid($request) {      
        $immediate = ($request['openid.mode'] == 'checkid_immediate');
        $version = $request->getVersion();
        
        $this->logger->log(LogLevel::INFO, 'OpenID authentication request: ' . (($immediate) ? 'immediate' : 'setup') . '; ', $request->toArray());

        // Check for protocol correctness    
        if ($version == Message::OPENID_VERSION_1_1) {
            if (!isset($request['openid.return_to'])) {
                $this->logger->log(LogLevel::ERROR, 'Protocol Error: openid.return_to not set.');
                $this->fatalError($this->f3->get('intl.core.openid.missing_return_to'));
                return;
            }
            if (!isset($request['openid.identity'])) {
                $this->logger->log(LogLevel::ERROR, 'Protocol Error: openid.identity not set.');
                $this->fatalError($this->f3->get('intl.core.openid.missing_identity'));
                return;
            }
        }

        if ($version == Message::OPENID_VERSION_2) {
            if (isset($request['openid.identity']) && !isset($request['openid.claimed_id'])) {
                $this->logger->log(LogLevel::ERROR, 'Protocol Error: openid.identity set, but not openid.claimed_id.');
                $this->fatalError($this->f3->get('intl.core.openid.missing_claimed_id'));
                return;
            }
            
            if (!isset($request['openid.realm']) && !isset($request['openid.return_to'])) {
                $this->logger->log(LogLevel::ERROR, 'Protocol Error: openid.return_to not set when openid.realm is not set.');
                $this->fatalError($this->f3->get('intl.core.openid.realm_but_no_return_to'));
                return;
            }
        }
        
        if (isset($request['openid.return_to'])) {
            $realm = $request->getRealm();
            
            if (!$request->returnToMatches($realm)) {
                $this->logger->log(LogLevel::ERROR, 'Protocol Error: openid.return_to does not match realm.');
                $this->indirectError($request['openid.return_to'], 'Protocol Error: openid.return_to does not match realm.', [], $request);
                return;
            }
        }
        
        if (isset($request['openid.identity'])) {
            // Standard request
            $this->logger->log(LogLevel::DEBUG, 'openid.identity found, use openIDCheckIdentity');
            $result = $this->openIDCheckIdentity($request, $immediate);
        } else {
            $this->logger->log(LogLevel::DEBUG, 'openid.identity not found, trying extensions');

            // Extension request
            $event = new OpenIDCheckEvent($request, $immediate);
            \Events::instance()->dispatch($event);

            $result = $event->getResult();
        }
        
        switch ($result) {
            case self::CHECKID_APPROVAL_REQUIRED:
                $this->logger->log(LogLevel::INFO, 'CHECKID_APPROVAL_REQUIRED');
                if ($immediate) {
                    $response = $this->createApprovalRequiredResponse($request);
                    $response->render($request['openid.return_to']);
                } else {
                    $response = $this->createOKResponse($request);
                    $this->consentForm($request, $response, $result);
                }
                break;
            case self::CHECKID_RETURN_TO_SUSPECT:
                $this->logger->log(LogLevel::INFO, 'CHECKID_RETURN_TO_SUSPECT');
                if ($immediate) {
                    $response = $this->createErrorResponse($request, $immediate);
                    $response->render($request['openid.return_to']);
                } else {
                    $response = $this->createOKResponse($request);
                    $this->consentForm($request, $response, $result);
                }
                break;
            case self::CHECKID_OK:
                $this->logger->log(LogLevel::INFO, 'CHECKID_OK');
                $this->logActivity($request);
                $response = $this->createOKResponse($request);
                $this->signResponse($response, isset($request['openid.assoc_handle']) ? $request['openid.assoc_handle'] : NULL);
                $response->render($request['openid.return_to']);
                break;
            case self::CHECKID_REENTER_CREDENTIALS:
            case self::CHECKID_LOGIN_REQUIRED:
                $this->logger->log(LogLevel::INFO, 'CHECKID_REENTER_CREDENTIALS | CHECKID_LOGIN_REQUIRED');
                if ($immediate) {
                    $response = $this->createLoginRequiredResponse($request, $result);
                    $response->render($request['openid.return_to']);
                } else {
                    $token = new SecurityToken();
                    $state = [ 'rq' => $request->toArray() ];
                    $form_state = new FormState([
                        'cancel' => 'openid',
                        'mode' => AuthManager::MODE_CREDENTIALS,
                        'auth_skip_activity' => true
                    ]);
                    $form_state->setRequest($request);
                    if ($result == self::CHECKID_REENTER_CREDENTIALS) {
                        $auth = AuthManager::instance();
                        $user = $auth->getUser();
                        $form_state['uid'] = $user['uid'];
                        $form_state['mode'] = AuthManager::MODE_REENTER_CREDENTIALS;
                    }

                    /** @var \SimpleID\Auth\AuthModule */
                    $auth_module = $this->mgr->getModule('SimpleID\Auth\AuthModule');
                    $auth_module->loginForm([
                        'destination' => 'continue/' . rawurlencode($token->generate($state))
                    ], $form_state);
                    exit;
                }
                break;
            case self::CHECKID_IDENTITIES_NOT_MATCHING:
            case self::CHECKID_IDENTITY_NOT_EXIST:
                $this->logger->log(LogLevel::INFO, 'CHECKID_IDENTITIES_NOT_MATCHING | CHECKID_IDENTITY_NOT_EXIST');
                $response = $this->createErrorResponse($request, $immediate);
                if ($immediate) {
                    $response->render($request['openid.return_to']);
                } else {                
                    $this->consentForm($request, $response, $result);                
                }
                break;
            case self::CHECKID_PROTOCOL_ERROR:
                if (isset($request['openid.return_to'])) {
                    $response = $this->createErrorResponse($request, $immediate);
                    $response->render($request['openid.return_to']);
                } else {
                    $this->fatalError('Unrecognised request.');
                }
                break;
        }
    }

    /**
     * Processes a standard OpenID authentication request about an identity.
     *
     * Checks whether the current user logged into SimpleID matches the identity
     * supplied in an OpenID request.
     *
     * @param Request $request the OpenID request
     * @param bool $immediate whether checkid_immediate was used
     * @return int one of CHECKID_OK, CHECKID_APPROVAL_REQUIRED, CHECKID_RETURN_TO_SUSPECT, CHECKID_IDENTITY_NOT_EXIST,
     * CHECKID_IDENTITIES_NOT_MATCHING, CHECKID_LOGIN_REQUIRED or CHECKID_PROTOCOL_ERROR
     */
    protected function openIDCheckIdentity($request, $immediate) {
        $auth = AuthManager::instance();
        $store = StoreManager::instance();
        $config = $this->f3->get('config');
        
        $realm = $request->getRealm();
        $cid = RelyingParty::buildID($realm);
        
        // Check 1: Is the user logged into SimpleID as any user?
        if (!$auth->isLoggedIn()) {
            return self::CHECKID_LOGIN_REQUIRED;
        } else {
            $user = $auth->getUser();
            $uid = $user['uid'];
        }
        
        // Check 2: Is the user logged in as the same identity as the identity requested?
        // Choose the identity URL for the user automatically
        if ($request['openid.identity'] == Request::OPENID_IDENTIFIER_SELECT) {
            $test_user = $store->loadUser($uid);
            $identity = $test_user['openid']['identity'];
            
            $this->logger->log(LogLevel::INFO, 'OpenID identifier selection: Selected ' . $uid . ' [' . $identity . ']');
        } else {
            $identity = $request['openid.identity'];
            /** @var \SimpleID\Models\User $test_user */
            $test_user = $store->findUser('openid.identity', $identity);
        }
        if ($test_user == NULL) return self::CHECKID_IDENTITY_NOT_EXIST;
        if ($test_user['uid'] != $user['uid']) {
            $this->logger->log(LogLevel::NOTICE, 'Requested user ' . $test_user['uid'] . ' does not match logged in user ' . $user['uid']);
            return self::CHECKID_IDENTITIES_NOT_MATCHING;
        }
        
        // Pass the assertion to extensions
        $event = new OpenIDCheckEvent($request, $immediate, $identity);
        \Events::instance()->dispatch($event);
        
        // Populate the request with the selected identity
        if ($request['openid.identity'] == Request::OPENID_IDENTIFIER_SELECT) {
            $request['openid.claimed_id'] = $identity;
            $request['openid.identity'] = $identity;
        }
        
        // Check 3: Discover the realm and match its return_to
        $client_prefs = (isset($user->clients[$cid])) ? $user->clients[$cid] : NULL;

        if (($request->getVersion() == Message::OPENID_VERSION_2) && $config['openid_verify_return_url']) {
            $verified = FALSE;
            
            $relying_party = $this->loadRelyingParty($realm);
            if ($relying_party->getServices() == null) {
                $services = [];
            } else {
                $services = $relying_party->getServices()->getByType(self::OPENID_RETURN_TO);
            }
            
            $this->logger->log(LogLevel::INFO, 'OpenID 2 discovery: ' . count($services) . ' matching services');
            
            if ($services) {
                $return_to_uris = [];
                
                foreach ($services as $service) {
                    $return_to_uris = array_merge($return_to_uris, $service['uri']);
                }
                foreach ($return_to_uris as $return_to) {
                    if ($request->returnToMatches($return_to, $config['openid_strict_realm_check'])) {
                        $this->logger->log(LogLevel::INFO, 'OpenID 2 discovery: verified');
                        $verified = TRUE;
                        break;
                    }
                }
            }
            
            if (!$verified) {
                if (($client_prefs != NULL) && isset($client_prefs['consents']['openid']) && $client_prefs['consents']['openid']) {
                    $this->logger->log(LogLevel::NOTICE, 'OpenID 2 discovery: not verified, but overridden by user preference');
                } else {
                    $this->logger->log(LogLevel::NOTICE, 'OpenID 2 discovery: not verified');
                    $event->setResult(self::CHECKID_RETURN_TO_SUSPECT);
                }
            }
        }
        
        // Check 4: For checkid_immediate, the user must already have given
        // permission to log in automatically.    
        if (($client_prefs != NULL) && isset($client_prefs['consents']['openid']) && $client_prefs['consents']['openid']) {
            $this->logger->log(LogLevel::INFO, 'Automatic set for realm ' . $realm);
            $event->setResult(self::CHECKID_OK);
            
            $final_assertion_result = $event->getResult();
            
            if ($final_assertion_result == self::CHECKID_OK) {
                if (!isset($user->clients[$cid])) $user->clients[$cid] = [];
                $user->clients[$cid]['last_time'] = time();
                $store->saveUser($user);
            }
            
            return $final_assertion_result;
        } else {
            $event->setResult(self::CHECKID_APPROVAL_REQUIRED);
            return $event->getResult();
        }
    }

    /**
     * Returns an OpenID response indicating a positive assertion.
     *
     * @param Request $request the OpenID request
     * @return Response an OpenID response with a positive assertion
     * @link http://openid.net/specs/openid-authentication-1_1.html#anchor17, http://openid.net/specs/openid-authentication-1_1.html#anchor23, http://openid.net/specs/openid-authentication-2_0.html#positive_assertions
     */
    protected function createOKResponse($request) {
        $rand = new Random();
        $nonce = gmstrftime('%Y-%m-%dT%H:%M:%SZ') . bin2hex($rand->bytes(4));

        $response = new Response($request);
        $response->setArray([
            'mode' => 'id_res',
            'op_endpoint' => $this->getCanonicalURL(),
            'response_nonce' => $nonce
        ]);
        
        if (isset($request['openid.assoc_handle'])) $response['assoc_handle'] = $request['openid.assoc_handle'];
        if (isset($request['openid.identity'])) $response['identity'] = $request['openid.identity'];
        if (isset($request['openid.return_to'])) $response['return_to'] = $request['openid.return_to'];
        
        if (($request->getVersion() == Message::OPENID_VERSION_2) && isset($request['openid.claimed_id'])) {
            $response['claimed_id'] = $request['openid.claimed_id'];
        }
        
        $event = new OpenIDResponseBuildEvent(true, $request, $response);
        \Events::instance()->dispatch($event);
        
        $this->logger->log(LogLevel::INFO, 'OpenID authentication response', $event->getResponse()->toArray());
        return $event->getResponse();
    }

    /**
     * Returns an OpenID response indicating a negative assertion to a
     * checkid_immediate request, where an approval of the relying party by the
     * user is required
     *
     * @param Request $request the OpenID request
     * @return Response an OpenID response with a negative assertion
     * @link http://openid.net/specs/openid-authentication-1_1.html#anchor17, http://openid.net/specs/openid-authentication-1_1.html#anchor23, http://openid.net/specs/openid-authentication-2_0.html#negative_assertions
     */
    protected function createApprovalRequiredResponse($request) {
        $response = new Response($request);

        if ($request->getVersion() == Message::OPENID_VERSION_2) {
            $response['mode'] = 'setup_needed';
        } else {
            $token = new SecurityToken();
            $state = [ 'rq' => $request->toArray() ];

            $request['openid.mode'] = 'checkid_setup';
            $response->setArray([
                'mode' => 'id_res',
                'user_setup_url' => $this->getCanonicalURL('auth/login/continue/' . rawurlencode($token->generate($state)))
            ]);
        }
        
        $event = new OpenIDResponseBuildEvent(false, $request, $response);
        \Events::instance()->dispatch($event);
        
        $this->logger->log(LogLevel::INFO, 'OpenID authentication response', $event->getResponse()->toArray());
        return $event->getResponse();
    }

    /**
     * Returns an OpenID response indicating a negative assertion to a
     * checkid_immediate request, where the user has not logged in.
     *
     * @param Request $request the OpenID request
     * @param int $result the authentication result providing the negative
     * assertion
     * @return Response an OpenID response with a negative assertion
     * @link http://openid.net/specs/openid-authentication-1_1.html#anchor17, http://openid.net/specs/openid-authentication-1_1.html#anchor23, http://openid.net/specs/openid-authentication-2_0.html#negative_assertions
     */
    protected function createLoginRequiredResponse($request, $result = self::CHECKID_LOGIN_REQUIRED) {
        $response = new Response($request);

        if ($request->getVersion() == Message::OPENID_VERSION_2) {
            $response['mode'] = 'setup_needed';
        } else {
            $token = new SecurityToken();
            $state = [ 'rq' => $request->toArray() ];
            $query = ($result == self::CHECKID_REENTER_CREDENTIALS) ? 'mode=' . AuthManager::MODE_REENTER_CREDENTIALS : '';

            $response->setArray([
                'mode' => 'id_res',
                'user_setup_url' => $this->getCanonicalURL('auth/login/continue/' . rawurlencode($token->generate($state)), $query)
            ]);
        }
        
        $event = new OpenIDResponseBuildEvent(false, $request, $response);
        \Events::instance()->dispatch($event);
        
        $this->logger->log(LogLevel::INFO, 'OpenID authentication response', $event->getResponse()->toArray());
        return $event->getResponse();
    }

    /**
     * Returns an OpenID response indicating a generic negative assertion.
     *
     * The content of the negative version depends on the OpenID version, and whether
     * the openid.mode of the request was checkid_immediate
     *
     * @param Request $request the OpenID request 
     * @param bool $immediate true if openid.mode of the request was checkid_immediate
     * @return Response an OpenID response with a negative assertion
     * @link http://openid.net/specs/openid-authentication-1_1.html#anchor17, http://openid.net/specs/openid-authentication-1_1.html#anchor23, http://openid.net/specs/openid-authentication-2_0.html#negative_assertions
     */
    protected function createErrorResponse($request, $immediate = false) {
        $response = new Response($request);
        $version = $request->getVersion();

        if ($immediate) {
            if ($version == Message::OPENID_VERSION_2) {
                $response['mode'] = 'setup_needed';
            } else {
                $response['mode'] = 'id_res';
            }
        } else {
            $response['mode'] = 'cancel';
        }
         
        $event = new OpenIDResponseBuildEvent(false, $request, $response);
        \Events::instance()->dispatch($event);
        
        $this->logger->log(LogLevel::INFO, 'OpenID authentication response', $event->getResponse()->toArray());
        return $event->getResponse();
    }

    /**
     * Signs an OpenID response, using signature information from an association
     * handle.
     *
     * @param Response $response the OpenID response
     * @param string $assoc_handle the association handle containing key information
     * for the signature.  If $assoc_handle is not specified, a private association
     * is created
     * @return Response the signed OpenID response
     */
    protected function signResponse($response, $assoc_handle = NULL) {
        $cache = \Cache::instance();
        
        if (!$assoc_handle) {
            $assoc = new Association(Association::ASSOCIATION_PRIVATE);
            $response['assoc_handle'] = $assoc->getHandle();
        } else {
            $assoc = $cache->get(rawurlencode($assoc_handle) . '.openid_association');
            
            if ($assoc->getCreationTime() + SIMPLEID_SHORT_TOKEN_EXPIRES_IN < time()) {
                // Association has expired, need to create a new one
                $this->logger->log(LogLevel::NOTICE, 'Association handle ' . $assoc->getHandle() . ' expired.  Using stateless mode.');
                $response['invalidate_handle'] = $assoc_handle;
                $assoc = new Association(Association::ASSOCIATION_PRIVATE);
                $response['assoc_handle'] = $assoc->getHandle();
            }
        }
        
        // If we are using stateless mode, then we need to cache the response_nonce
        // so that the RP can only verify once
        if ($assoc->isPrivate() && isset($response['response_nonce'])) {
            $cache->set(rawurlencode($response['response_nonce']) . '.openid_response' , [
                'response_nonce' => $response['response_nonce'],
                'association' => $assoc
            ], SIMPLEID_SHORT_TOKEN_EXPIRES_IN);
        }
        
        $response['sig'] = $assoc->sign($response);
        
        $this->logger->log(LogLevel::INFO, 'OpenID signed authentication response', $response->toArray());
        
        return $response;
    }

    /**
     * Processes a direct verification request.  This is used in the OpenID specification
     * to verify signatures generated using stateless mode.
     *
     * @param Request $request the OpenID request
     * @return void
     * @see http://openid.net/specs/openid-authentication-1_1.html#mode_check_authentication, http://openid.net/specs/openid-authentication-2_0.html#verifying_signatures
     */
    protected function check_authentication($request) {
        $this->logger->log(LogLevel::DEBUG, 'SimpleID\Protocols\OpenID\OpenIDModule->check_authentication');
        $this->logger->log(LogLevel::INFO, 'OpenID direct verification', $request->toArray());

        $cache = \Cache::instance();
        
        $response = new Response($request);
        $response['is_valid'] = ($this->verifySignatures($request)) ? 'true' : 'false';

        // RP wants to check whether a handle is invalid
        if (isset($request['openid.invalidate_handle'])) {
            $invalid_assoc = $cache->get(rawurlencode($request['openid.invalidate_handle']) . 'openid_association');
            
            if (!$invalid_assoc || ($invalid_assoc->getCreationTime() + SIMPLEID_SHORT_TOKEN_EXPIRES_IN < time())) {
                // Yes, it's invalid
                $response['invalidate_handle'] = $request['openid.invalidate_handle'];
            }
        }

        $this->logger->log(LogLevel::INFO, 'OpenID direct verification response', $response->toArray());
        
        $response->render();
    }

    /**
     * Verifies the signature of a signed OpenID request/response.
     *
     * @param Request $request the OpenID request/response
     * @return bool true if the signature is verified
     * @since 0.8
     */
    protected function verifySignatures($request) {
        $cache = \Cache::instance();

        // rawurlencode is used to ensure potentially dangerous input is made safe
        $stateless = (isset($request['openid.response_nonce'])) ? $cache->get(rawurlencode($request['openid.response_nonce']) . '.openid_response') : NULL;
        if ($stateless == NULL) {
            $this->logger->log(LogLevel::NOTICE, 'Response nonce not found: ' . $request['openid.response_nonce']);
            return false;
        }
        $cache->clear(rawurlencode($request['openid.response_nonce']) . '.openid_response');

        $association = $stateless['association'];
      
        if (!$association->isPrivate()) {
            $this->logger->log(LogLevel::WARNING, 'Attempting to verify an association with a shared key.');
            return FALSE;
        }

        if ($association->getHandle() != $request['openid.assoc_handle']) {
            $this->logger->log(LogLevel::WARNING, 'Attempting to verify a response_nonce more than once, or private association expired.');
            return FALSE;
        } else {
            $signature = $association->sign($request);
            $this->logger->log(LogLevel::DEBUG, '***** Signature: ' . $signature);
            
            if ($signature != $request['openid.sig']) {
                $this->logger->log(LogLevel::WARNING, 'Signature supplied in request does not match the signature generated.');
                return FALSE;
            }
        }
        
        return true;
    }

    /**
     * Provides a form for user consent of an OpenID relying party, where the 
     * {@link simpleid_checkid_identity()} function returns a CHECKID_APPROVAL_REQUIRED
     * or CHECKID_RETURN_TO_SUSPECT.
     *
     * Alternatively, provide a form for the user to rectify the situation where
     * {@link simpleid_checkid_identity()} function returns a CHECKID_IDENTITIES_NOT_MATCHING
     * or CHECKID_IDENTITY_NOT_EXIST
     *
     * @param Request $request the original OpenID request
     * @param Response $response the proposed OpenID response, subject to user
     * verification
     * @param int $reason either CHECKID_APPROVAL_REQUIRED, CHECKID_RETURN_TO_SUSPECT,
     * CHECKID_IDENTITIES_NOT_MATCHING or CHECKID_IDENTITY_NOT_EXIST
     * @return void
     */
    protected function consentForm($request, $response, $reason = self::CHECKID_APPROVAL_REQUIRED) {
        $tpl = new \Template();
        $token = new SecurityToken();
        $auth = AuthManager::instance();
        $user = $auth->getUser();

        $form_state = new FormState([
            'code' => $reason
        ]);
        $form_state->setRequest($request);
        $form_state->setResponse($response);
        $cancel = ($response['mode'] == 'cancel');

        $realm = $request->getRealm();

        $this->f3->set('realm', $realm);

        if ($cancel) {
            $this->f3->set('requested_identity', $request['openid.identity']);
            $this->f3->set('switch_url', $this->getCanonicalURL('auth/logout/continue/' .  rawurlencode($token->generate($request->toArray())), '', 'detect'));
        } else {
            $base_path = $this->f3->get('base_path');
            
            $form_state['prefs'] = (isset($user->clients[$realm])) ? $user->clients[$realm] : [];

            $event = new FormBuildEvent($form_state, 'openid_consent_form_build');
            \Events::instance()->dispatch($event);
            $this->f3->set('forms', $event->getBlocks());
            
            if ($reason == self::CHECKID_RETURN_TO_SUSPECT) {
                $this->f3->set('return_to_suspect', true);
                $this->f3->set('suspect_url', 'http://simpleid.org/documentation/troubleshooting/returnto-discovery-failure');
                $this->f3->set('js_locale', [ 'openid_suspect' => addslashes($this->f3->get('intl.core.openid.suspect_js_1')) . '\n\n' . addslashes($this->f3->get('intl.core.openid.suspect_js_2')) ]);
            }
        }
        
        $this->f3->set('tk', $token->generate('openid_consent', SecurityToken::OPTION_BIND_SESSION));
        $this->f3->set('fs', $token->generate($form_state->encode()));

        $this->f3->set('cancel', $cancel);

        $this->f3->set('logout_destination', '/continue/' . rawurlencode($token->generate($request->toArray())));
        $this->f3->set('user_header', true);
        $this->f3->set('title', $this->f3->get('intl.core.openid.openid_title'));
        $this->f3->set('page_class', 'dialog-page');
        $this->f3->set('layout', 'openid_consent.html');
        
        header('X-Frame-Options: DENY');
        print $tpl->render('page.html');
    }

    /**
     * Processes a user response from the {@link simpleid_openid_consent_form()} function.
     *
     * If the user verifies the relying party, an OpenID response will be sent to
     * the relying party.  Otherwise, the dashboard will be displayed to the user.
     * 
     * @return void
     */
    public function consent() {
        $auth = AuthManager::instance();
        $token = new SecurityToken();
        $store = StoreManager::instance();
    
        if (!$auth->isLoggedIn()) {
            /** @var \SimpleID\Auth\AuthModule */
            $auth_module = $this->mgr->getModule('SimpleID\Auth\AuthModule');
            $auth_module->loginForm();
            return;
        }
        $user = $auth->getUser();

        $form_state = FormState::decode($token->getPayload($this->f3->get('POST.fs')), Request::class, Response::class);
        /** @var Request */
        $request = $form_state->getRequest();
        /** @var Response */
        $response = $form_state->getResponse();
        $reason = $form_state['code'];

        if (!$token->verify($this->f3->get('POST.tk'), 'openid_consent')) {
            $this->logger->log(LogLevel::WARNING, 'Security token ' . $this->f3->get('POST.tk') . ' invalid.');
            $this->f3->set('message', $this->f3->get('intl.common.invalid_tk'));
            $this->consentForm($request, $response, $reason);
            return;
        }
    
        $return_to = $response['return_to'];
        if ($return_to == null) $return_to = $request['openid.return_to'];
    
        if ($this->f3->get('POST.op') == $this->f3->get('intl.common.cancel')) {
            $response = $this->createErrorResponse($request, false);
            if (!$return_to) $this->f3->set('message', $this->f3->get('intl.common.login_cancelled'));
        } else {
            $event = new FormSubmitEvent($form_state, 'openid_consent_form_submit');
            \Events::instance()->dispatch($event);

            $consents = [ 'openid' => ($this->f3->exists('POST.prefs.consents.openid') && ($this->f3->get('POST.prefs.consents.openid') == 'true')) ];
            $this->logActivity($request, $consents);
            
            $this->signResponse($response, isset($response['assoc_handle']) ? $response['assoc_handle'] : NULL);
            if (!$return_to) $this->f3->set('message', $this->f3->get('intl.common.login_success'));
        }

        if ($return_to) {
            $response->render($return_to);
        } else {
            $this->f3->reroute('/');
        }
    }

    /**
     * Processes a cancellation from the login form.
     *
     * @param FormSubmitEvent $event the form cancellation
     * event
     * @return void
     */
    public function onLoginFormCancel(FormSubmitEvent $event) {
        $form_state = $event->getFormState();

        if ($form_state['cancel'] == 'openid') {
            /** @var \SimpleID\Protocols\OpenID\Request */
            $request = $form_state->getRequest();
            if (isset($request['openid.return_to'])) {
                $return_to = $request['openid.return_to'];
                $response = $this->createErrorResponse($request, FALSE);
                $response->render($return_to);
                $event->stopPropagation();
                return;
            }
        }
    }

    /**
     * Logs the authentication activity against the user.
     *
     * @param Request $request the OpenID request
     * @param array<string, mixed>|null $consents if not `null`, saves the consents
     * @return void
     */
    protected function logActivity($request, $consents = NULL) {
        $store = StoreManager::instance();

        $auth = AuthManager::instance();
        $user = $auth->getUser();

        $realm = $request->getRealm();
        $cid = RelyingParty::buildID($realm);
        $relying_party = $this->loadRelyingParty($realm, true);

        $now = time();

        $activity = [
            'type' => 'app',
            'id' => $realm,
            'time' => $now
        ];
        if ($this->f3->exists('IP')) $activity['remote'] = $this->f3->get('IP');
        $user->addActivity($cid, $activity);

        if (isset($user->clients[$cid])) {
            $prefs = $user->clients[$cid];
        } else {
            $prefs = [
                'openid' => [
                    'version' => $request->getVersion()
                ],
                'store_id' => $relying_party->getStoreID(),
                'display_name' => $relying_party->getDisplayName(),
                'display_html' => $relying_party->getDisplayHTML(),
                'first_time' => $now,
                'consents' => []
            ];
        }

        $prefs['last_time'] = $now;

        if ($consents != null) {
            $prefs['consents'] = $consents;
        }
            
        $user->clients[$cid] = $prefs;
        $store->saveUser($user);
    }


    /**
     * Sends a direct message indicating an error.  This is a convenience function
     * for {@link renderDirectResponse()}.
     *
     * @param string $error the error message
     * @param array<string, string> $additional any additional data to be sent with the error
     * message
     * @param Request $request the request in response to which the error is made
     * @return void
     */
    protected function directError($error, $additional = [], $request = NULL) {
        $this->f3->status(400);

        $error = Response::createError($error, $additional, $request);
        $error->render();
    }

    /**
     * Sends an indirect message indicating an error.  This is a convenience function
     * for {@link openid_indirect_response()}.
     *
     * @param string $url the URL to which the error message is to be sent
     * @param string $error the error message or code
     * @param array<string, string> $additional any additional data to be sent with the error
     * message
     * @param Request $request the request in response to which the error is made
     * @return void
     */
    protected function indirectError($url, $error, $additional = [], $request = NULL) {
        $error = Response::createError($error, $additional, $request);
        $error->render($url);
    }

    /**
     * Obtains information on a relying party by performing discovery on them.  Information
     * obtained includes the discovery URL, the parsed XRDS document, and any other
     * information saved by SimpleID extensions
     *
     * @param string $realm the openid.realm parameter
     * @param bool $allow_stale allow stale results to be returned, otherwise discovery
     * will occur
     * @return RelyingParty containing information on a relying party.
     * @link http://openid.net/specs/openid-authentication-2_0.html#rp_discovery
     * @since 0.8
     */
    public function loadRelyingParty($realm, $allow_stale = false) {
        $store = StoreManager::instance();

        $cid = RelyingParty::buildID($realm);

        /** @var RelyingParty $relying_party */
        $relying_party = $store->loadClient($cid);
        if ($relying_party == null) $relying_party = new RelyingParty($realm);

        if ((time() - $relying_party->getDiscoveryTime() > SIMPLEID_SHORT_TOKEN_EXPIRES_IN) && !$allow_stale) {
            $this->logger->log(LogLevel::INFO, 'OpenID 2 RP discovery: realm: ' . $realm);
            $relying_party->discover();
            $store->saveClient($relying_party);
        }

        return $relying_party;
    }

    /**
     * Displays the XRDS document for this SimpleID installation.
     * 
     * @return void
     */
    public function providerXRDS() {
        $this->logger->log(LogLevel::DEBUG, 'Providing XRDS.');

        $tpl = new \Template();

        $event = new BaseDataCollectionEvent('xrds_types');
        \Events::instance()->dispatch($event);
        
        $this->f3->set('types', $event->getResults());
        
        header('Content-Disposition: inline; filename=yadis.xml');
        print $tpl->render('openid_provider_xrds.xml', 'application/xrds+xml');
    }


    /**
     * Returns the user's public XRDS page.
     * 
     * @param \Base $f3
     * @param array<string, mixed> $params
     * @return void
     */
    public function userXRDS($f3, $params) {
        $store = StoreManager::instance();
        $user = $store->loadUser($params['uid']);
        
        if ($user != NULL) {
            $tpl = new \Template();

            if ($user->hasLocalOpenIDIdentity()) {
                $this->f3->set('local_id', $user['openid']["identity"]);
            }
            header('Content-Disposition: inline; filename=yadis.xml');
            print $tpl->render('openid_user_xrds.xml', 'application/xrds+xml');
        } else {
            $this->f3->status(404);
            
            $this->fatalError($this->f3->get('intl.common.user_not_found', $params['uid']));
        }
    }

    /**
     * Returns the OpenID Connect scopes supported by this server.
     *
     * @return void
     * @since 2.0
     */
    public function onScopeInfoCollectionEvent(ScopeInfoCollectionEvent $event) {
        $event->addScopeInfo('openid', [
            self::DEFAULT_SCOPE => [
                'description' => $this->f3->get('intl.common.scope.id'),
            ]
        ]);
    }

    /**
     * Returns a block containing discovery information.
     *
     * @param UIBuildEvent $event the event to collect
     * the discovery block
     * @return void
     */
    public function onProfileBlocks(UIBuildEvent $event) {
        $auth = AuthManager::instance();
        $user = $auth->getUser();
        $tpl = new \Template();
        
        $this->f3->set('js_locale', [ 'code' => addslashes($this->f3->get('intl.core.openid.profile_js')) ]);

        $xrds_url = $this->getCanonicalURL('user/'. $user['uid'] . '/xrds', '', 'detect');
        $hive = [
            'config' => $this->f3->get('config'),
            'intl' => $this->f3->get('intl'),
            'user' => $user,
            'xrds_url' => $xrds_url
        ];
        
        $event->addBlock('discovery', $tpl->render('openid_profile.html', false, $hive), 1, [
            'title' => $this->f3->get('intl.core.openid.discovery_title'),
            'links' => [ [ 'href' => 'http://simpleid.org/documentation/getting-started/setting-identity/claim-your-identifier', 'name' => $this->f3->get('intl.common.more_info') ] ],
        ]);
    }
}

?>
