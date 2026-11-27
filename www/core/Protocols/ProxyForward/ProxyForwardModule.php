<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2025
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

namespace SimpleID\Protocols\ProxyForward;

use Psr\Log\LogLevel;
use SimpleID\Module;
use SimpleID\Base\RequestState;
use SimpleID\Auth\AuthManager;
use SimpleID\Store\StoreManager;
use SimpleID\Crypt\SecurityToken;
use \Audit;

/**
 * A module implementing the forward authentication used by reverse
 * proxies.
 */
class ProxyForwardModule extends Module {
    /**
     * Constant for `forward_auth` mode, used by Caddy and Traefik
     */
    const MODE_FORWARD_AUTH = 'forward_auth';
    /**
     * Constant for `auth_request` mode, used by nginx
     */
    const MODE_AUTH_REQUEST = 'auth_request';

    static function init($f3) {
        $f3->route('GET|POST: /proxyforward/start/@mode/@client_id', 'SimpleID\Protocols\ProxyForward\ProxyForwardModule->start');
        $f3->route('GET: /proxyforward/continue', 'SimpleID\Protocols\ProxyForward\ProxyForwardModule->continue');
    }

    /**
     * Processes a forward authentication request
     * 
     * @param \Base $f3
     * @param array<string, mixed> $params
     * @return void
     */ 
    function start($f3, $params) {
        $audit = new Audit();
        $auth = AuthManager::instance();
        $store = StoreManager::instance();

        // 1. Check mode
        if (!isset($params['mode'])) {
            $this->fatalError($this->f3->get('intl.core.proxyforward.missing_mode'), 400);
            return;
        }        
        $mode = $params['mode'];
        $this->logger->log(LogLevel::INFO, 'Forward authentication request: ' . $params['mode']);

        // 2. Get the forwarded URL
        switch ($mode) {
            case self::MODE_FORWARD_AUTH:
                if (!$this->f3->exists('HEADERS.X-Forwarded-Proto') || !$this->f3->exists('HEADERS.X-Forwarded-Host') || @$this->f3->exists('HEADERS.X-Forwarded-Uri')) {
                    $this->logger->log(LogLevel::ERROR, 'Missing X-Forwarded-Proto, X-Forwarded-Host or X-Forwarded-Uri header');
                    $this->fatalError($this->f3->get('intl.core.proxyforward.missing_header'), 400);
                    return;
                }
                $forwarded_url = $this->f3->get('HEADERS.X-Forwarded-Proto') . '://'
                    . $this->f3->get('HEADERS.X-Forwarded-Host') . $this->f3->get('HEADERS.X-Forwarded-Uri');

                $is_interactive = ($audit->isdesktop() || $audit->ismobile());
                break;
            case self::MODE_AUTH_REQUEST:
                if (!$this->f3->exists('HEADERS.X-Original-Url')) {
                    $this->logger->log(LogLevel::ERROR, 'Missing X-Original-Url header');
                    $this->fatalError($this->f3->get('intl.core.proxyforward.missing_header'), 400);
                    return;
                }
                $forwarded_url = $this->f3->get('HEADERS.X-Original-Url');

                $parts = parse_url($forwarded_url);
                if ($parts == false) {
                    $this->logger->log(LogLevel::ERROR, 'Cannot parse X-Original-Url header');
                    $this->fatalError($this->f3->get('intl.core.proxyforward.missing_header'), 400);
                    return;
                }
                if (!isset($parts['scheme']) || !isset($parts['host'])) {
                    $this->logger->log(LogLevel::ERROR, 'X-Original-Url header does not contain scheme or host');
                    $this->fatalError($this->f3->get('intl.core.proxyforward.missing_header'), 400);
                    return;
                }

                // nginx does not support redirects
                $is_interactive = false;
                break;
            default:
                $this->fatalError($this->f3->get('intl.core.proxyforward.missing_mode'), 400);
                return;
        }
        
        // 3. Check that forwarded URL is authorised by the client
        if (!isset($params['client_id'])) {
            $this->fatalError($this->f3->get('intl.core.oauth.missing_client_id'), 400);
            return;
        }

        $client = $store->loadClient($params['client_id']);
        if ($client == NULL) {
            $this->logger->log(LogLevel::ERROR, 'Client with client_id not found: ' . $params['client_id']);
            $this->fatalError($this->f3->get('intl.core.oauth.client_not_found'), 400);
            return;
        }

        $origin = $this->getOrigin($forwarded_url);
        $origin_allowed = false;
        foreach ($client->get('proxyforward.allow_origins') as $allowed_origin) {
            if (strcasecmp($origin, $allowed_origin) === 0) {
                $origin_allowed = true;
                break;
            }
        }

        if (!$origin_allowed) {
            $this->logger->log(LogLevel::ERROR, 'Origin ' . $origin . ' not allowed for client ' . $params['client_id']);
            $this->unauthorisedResponse($is_interactive);
            return;
        }

        // 4. Check whether it is authenticated
        if (!$auth->isLoggedIn()) {
            $this->unauthorisedResponse($is_interactive, $forwarded_url);
            return;
        }

        // 5. Construct response
        $user = $auth->getUser();

        $this->f3->status(200);

        header('Remote-User: ' . $this->filter_header($user['uid']));
        header('Remote-Name: ' . $this->filter_header($user->get('userinfo.name')));
        header('Remote-Email: ' . $this->filter_header($user->get('userinfo.email')));

        print '200 OK';
    }

    /**
     * @return void
     */
    function continue() {
        if (!$this->f3->exists('REQUEST.fw')) {
            $this->fatalError($this->f3->get('intl.common.invalid_request'), 400);
            return;
        }

        $token = new SecurityToken();
        $forwarded_url = $token->getPayload($this->f3->get('REQUEST.fw'));

        if ($forwarded_url === null) {
            $this->fatalError($this->f3->get('intl.common.invalid_request'), 400);
            return;
        }

        $this->f3->status(303);
        header('Location: ' . $forwarded_url);
    }

    /**
     * @return void
     */
    protected function unauthorisedResponse(bool $is_interactive = false, ?string $forwarded_url = null) {
        if ($forwarded_url != null) {
            $token = new SecurityToken();
            $request_state = new RequestState();

            $request_state->setRoute('/proxyforward/continue');
            $request_state->setParams(['fw' => $token->generate($forwarded_url)]);
            
            $redirect_url = $this->getCanonicalURL('auth/login/continue/' . rawurlencode($token->generate($request_state)));
        } else {
            $redirect_url = null;
        }

        if ($is_interactive && $redirect_url != null) {
            // redirect to uri
            $this->f3->status(302); // Check whether it should be 303
            header('Location: ' . $redirect_url);
        } else {
            // Return 401, encode redirect uri in header
            $this->f3->status(401);
            if ($redirect_url != null) header('X-Redirect-Location: ' . $redirect_url);
            header('Content-Type: text/plain');
            print '401 Unauthorized';
        }
    }

    /**
     * Filters a string by removing all characters other than printable
     * ASCII characters and a tab.
     * 
     * @param string $input the string to filter
     * @return string the filtered string
     */
    protected function filter_header(string $input): string {
        return preg_replace('/[^\x09\x20-\x7E]/', '', $input);
    }
}


?>
