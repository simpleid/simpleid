<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2009-2025
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

use SimpleID\Auth\AuthManager;
use SimpleID\Module;
use SimpleID\ModuleManager;
use SimpleID\Base\ConsentEvent;
use SimpleID\Protocols\ProtocolResultEvent;
use SimpleID\Store\StoreManager;
use SimpleID\Util\SecurityToken;
use SimpleID\Util\Events\OrderedDataCollectionEvent;
use SimpleID\Util\Events\UIBuildEvent;
use SimpleID\Util\UI\Template;

/**
 * Functions for displaying various pages in SimpleID.
 *
 * @since 0.7
 */
class MyModule extends Module {
    static function init($f3) {
        $f3->route('GET /my/dashboard', 'SimpleID\Base\MyModule->dashboard');
        $f3->route('GET /my/apps [sync]', 'SimpleID\Base\MyModule->apps_sync');
        $f3->route('GET /my/profile', 'SimpleID\Base\MyModule->profile');
        /* AJAX handlers */
        $f3->route('GET /my/apps [ajax]', 'SimpleID\Base\MyModule->apps_ajax');
        $f3->map('/my/apps/@cid', 'SimpleID\Base\MyModule');
    }

    public function beforeroute() {
        parent::beforeroute();

        $auth = AuthManager::instance();
        if (!$auth->isLoggedIn()) {
            if ($this->f3->get('AJAX')) {
                $this->f3->status(401);
                header('Content-Type: application/json');
                print json_encode([
                    'error' => 'unauthorized',
                    'error_description' => $this->f3->get('intl.common.unauthorized')
                ]);
                exit;
            } else {
                $route = ltrim($this->f3->get('PARAMS.0'), '/');
                $this->f3->reroute('@auth_login(1=' . $route . ')');
            }
        }

        if (!$this->f3->get('AJAX')) {
            $this->f3->set('user_header', true);
            $this->f3->set('logout_link', true);
            $this->insertNav();
        }
    }

    /**
     * Displays the dashboard page.
     * 
     * @return void
     */
    public function dashboard() {
        $this->blocksPage($this->f3->get('intl.core.my.dashboard_title'), 'dashboard_blocks');
    }

    /**
     * Displays the profile page.
     * 
     * @return void
     */
    public function profile() {
        $this->blocksPage($this->f3->get('intl.core.my.profile_title'), 'profile_blocks');
    }

    /**
     * Returns the sites page.
     * 
     * @return void
     */
    public function apps_sync() {
        // Require HTTPS, redirect if necessary
        $this->checkHttps('redirect', true);

        $token = new SecurityToken();

        $tpl = Template::instance();
        $this->f3->set('tk', $token->generate('apps', SecurityToken::OPTION_BIND_SESSION));
        $this->f3->set('title', $this->f3->get('intl.core.my.apps_title'));
        $this->f3->set('js_data.intl', [
            'first_time_label' => $this->f3->get('intl.core.my.first_time_label'),
            'last_time_label' => $this->f3->get('intl.core.my.last_time_label'),
            'consents_label' => $this->f3->get('intl.core.my.consents_label')
        ]);
        $this->f3->set('layout', 'my_apps.html');
        print $tpl->render('page.html');
    }

    /**
     * @return void
     */
    public function apps_ajax() {
        $this->checkHttps('error', true);

        header('Content-Type: application/json');

        $token = new SecurityToken();
        if (!$this->f3->exists('HEADERS.X-Request-Token') || !$token->verify($this->f3->get('HEADERS.X-Request-Token'), 'apps')) {
            $this->f3->status(401);
            print json_encode([
                'error' => 'unauthorized',
                'error_description' => $this->f3->get('intl.common.unauthorized')
            ]);
            return;
        }

        $auth = AuthManager::instance();
        $user = $auth->getUser();
        $prefs = $user->clients;

        uasort($prefs, function ($a, $b) {
            return strcasecmp($a['display_name'], $b['display_name']);
        });

        $event = new ScopeInfoCollectionEvent();
        \Events::instance()->dispatch($event);
        $scope_info = $event->getAllScopeInfo();

        $results = [];
        foreach ($prefs as $cid => $client_prefs) {
            $consent_info = [];
            foreach ($client_prefs['consents'] as $type => $consents) {
                if (is_array($consents)) {
                    foreach ($consents as $consent) {
                        $consent_info[] = [
                            'description' => isset($scope_info[$type][$consent]['description']) ? $scope_info[$type][$consent]['description'] : $type . ':' . $consent,
                            'weight' => isset($scope_info[$type][$consent]['weight']) ? $scope_info[$type][$consent]['description'] : 0
                        ];
                    }
                } elseif ($consents) {
                    $consent_info[] = [
                        'description' => isset($scope_info[$type]['description']) ? $scope_info[$type]['description'] : $type,
                        'weight' => isset($scope_info[$type]['weight']) ? $scope_info[$type]['description'] : 0
                    ];
                }
            }
            usort($consent_info, function ($a, $b) {
                return $a['weight'] - $b['weight'];
            });

            $results[] = [
                'cid' => $cid,
                'display_name' => $client_prefs['display_name'],
                'display_html' => $client_prefs['display_html'],
                'first_time' => $this->f3->format('{0,date} {0,time}', $client_prefs['first_time']),
                'last_time' => $this->f3->format('{0,date} {0,time}', $client_prefs['last_time']),
                'consents' => $consent_info
            ];
        }

        print json_encode($results);
    }

    /**
     * @param \Base $f3
     * @param array<string, mixed> $params
     * @return void
     */
    public function delete($f3, $params) {
        $this->checkHttps('error', true);
        parse_str($this->f3->get('BODY'), $delete);

        header('Content-Type: application/json');

        $token = new SecurityToken();
        if (!$this->f3->exists('HEADERS.X-Request-Token') || !$token->verify($this->f3->get('HEADERS.X-Request-Token'), 'apps')) {
            $this->f3->status(401);
            print json_encode([
                'error' => 'unauthorized',
                'error_description' => $this->f3->get('intl.common.unauthorized'),
            ]);
            return;
        }

        $auth = AuthManager::instance();
        $user = $auth->getUser();
        $prefs = &$user->clients;
        if (!isset($prefs[$params['cid']])) {
            $this->f3->status(404);
            print json_encode([
                'error' => 'not_found',
                'error_description' => $this->f3->get('intl.common.not_found')
            ]);
            return;
        }

        $event = new ConsentEvent('consent_revoke', $user, $params['cid'], $prefs[$params['cid']]);
        \Events::instance()->dispatch($event);

        unset($prefs[$params['cid']]);
        
        $store = StoreManager::instance();
        $store->saveUser($user);

        print json_encode([
            'result' => 'success',
            'result_description' => $this->f3->get('intl.core.my.app_delete_success')
        ]);
    }

    /**
     * @return void
     */
    public function onNav(OrderedDataCollectionEvent $event) {
        $event->addResult([ 'name' => $this->f3->get('intl.core.my.dashboard_title'), 'path' =>'my/dashboard' ], -10);
        $event->addResult([ 'name' => $this->f3->get('intl.core.my.profile_title'), 'path' =>'my/profile' ], -9);
        $event->addResult([ 'name' => $this->f3->get('intl.core.my.apps_title'), 'path' =>'my/apps' ], -8);
    }

    /**
     * Returns the welcome block.
     *
     * @param UIBuildEvent $event the event to pick up the welcome block
     * @return void
     */
    public function onDashboardBlocks(UIBuildEvent $event) {
        $auth = AuthManager::instance();
        $user = $auth->getUser();
        $tpl = Template::instance();

        $event->addBlock('welcome', $this->f3->get('intl.core.my.logged_in_as', [ $user->getDisplayName(), $user['uid'] ]), -10, [
            'title' => $this->f3->get('intl.core.my.welcome_title')
        ]);

        $event->addBlock('activity', $tpl->render('my_activity.html', false), 0, [
            'title' => $this->f3->get('intl.core.my.activity_title')
        ]);

        if ($this->f3->get('config.debug')) {
            $event->addBlock('auth', '<pre class="code">' . $this->f3->encode($auth->toString()) . '</pre>', 10, [
                'title' => $this->f3->get('intl.core.my.debug_auth_title')
            ]);

            $event->addBlock('user', '<pre class="code">' . $this->f3->encode($user->toString()) . '</pre>', 10, [
                'title' => $this->f3->get('intl.core.my.debug_user_title')
            ]);
        }
    }

    /**
     * Saves a positive assertion result to the user's activity log.
     * 
     * @param ProtocolResultEvent $event the assertion result event
     * @return void
     */
    public function onProtocolResultEvent(ProtocolResultEvent $event) {
        if ($event->isPositiveAssertion()) {
            /** @var \SimpleID\Models\User $user */
            $user = $event->getSubject();
            $client_id = $event->getClient()->getStoreID();

            $activity = [
                'type' => 'app',
                'id' => $client_id,
                'time' => $event->getTime()->getTimestamp()
            ];
            if ($event->getIP()) $activity['remote'] = $event->getIP();
            $user->addActivity($client_id, $activity);
        }
    }

    /**
     * @return void
     */
    public function insertNav() {
        $event = new OrderedDataCollectionEvent('nav');
        \Events::instance()->dispatch($event);
        $this->f3->set('nav', $event->getResults());
    }

    /**
     * Generic function to display a page comprising blocks returned
     * from a hook.
     *
     * @param string $title the page title
     * @param string $event_name the hook to call
     * @return void
     */
    protected function blocksPage($title, $event_name) {
        // Require HTTPS, redirect if necessary
        $this->checkHttps('redirect', true);

        $event = new UIBuildEvent($event_name);
        \Events::instance()->dispatch($event);

        $tpl = Template::instance();
        $tpl->mergeAttachments($event);
        $this->f3->set('blocks', $event->getBlocks());
        $this->f3->set('title', $title);
        $this->f3->set('layout', 'my_blocks.html');
        print $tpl->render('page.html');
    }
}

?>
