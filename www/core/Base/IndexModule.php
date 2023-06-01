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

namespace SimpleID\Base;

use Psr\Log\LogLevel;
use SimpleID\Auth\AuthManager;
use SimpleID\Module;
use SimpleID\ModuleManager;
use SimpleID\Util\SecurityToken;

/**
 * This module contains generic routes for SimpleID.
 */
class IndexModule extends Module {
    static function init($f3) {
        $f3->route('GET|POST /', 'SimpleID\Base\IndexModule->index');
        $f3->route('GET|POST /continue/@token', 'SimpleID\Base\IndexModule->continueRequest');
    }

    /**
     * The default route, called when the q parameter is missing or is invalid.
     *
     * This function performs the following:
     *
     * - This calls the index hook to determine whether other modules would handle this
     *   request
     * - Otherwise, if MyModule is loaded, the dashboard is displayed
     * - If MyModule is not loaded, a blank page is displayed
     *
     * @return void
     */
    public function index() {
        $mgr = ModuleManager::instance();

        $this->logger->log(LogLevel::DEBUG, 'SimpleID\Base\IndexModule->index');
        header('Vary: Accept');

        $event = new IndexEvent($_REQUEST);
        $dispatcher = \Events::instance();
        $dispatcher->dispatch($event);
        if ($event->isPropagationStopped()) return;

        $auth = AuthManager::instance();
    
        if (!$auth->isLoggedIn()) {
            /** @var \SimpleID\Auth\AuthModule $auth_module */
            $auth_module = $mgr->getModule('SimpleID\Auth\AuthModule');
            $auth_module->loginForm();
        } elseif ($mgr->isModuleLoaded('SimpleID\Base\MyModule')) {
            $this->f3->mock('GET /my/dashboard');
        } else {
            $tpl = \Template::instance();
            $this->f3->set('user_header', true);
            $this->f3->set('title', 'SimpleID');
            print $tpl->render('page.html');
        }
    }

    /**
     * Continues a previously saved request.
     *
     * The request is saved as a <code>SecurityToken</code> which is passed through
     * the <code>token</code> path parameter.  The underlying payload
     * can contain the following keys
     *
     * - mt the HTTP method (e.g. GET, POST)
     * - rt the FatFree routing path
     * - rq an array containing the request parameters
     * 
     * @param \Base $f3
     * @param array<string, mixed> $params
     * @return void
     */
    public function continueRequest($f3, $params) {
        $token = new SecurityToken();
        $payload = $token->getPayload($params['token']);

        if ($payload === null) {
            $this->fatalError($this->f3->get('intl.common.invalid_request'));
            return;
        }
        
        if (!isset($payload['mt'])) $payload['mt'] = 'GET';
        if (!isset($payload['rt'])) $payload['rt'] = '/';
        if (!isset($payload['rq'])) $payload['rq'] = [];
        
        $this->f3->mock($payload['mt'] . ' ' . $payload['rt'], $payload['rq']);
    }

}

?>