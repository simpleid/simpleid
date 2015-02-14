<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2009
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
use SimpleID\Store\StoreManager;
use SimpleID\Util\SecurityToken;

/**
 * Functions for displaying various pages in SimpleID.
 *
 * @since 0.7
 */
class MyModule extends Module {
    static function routes($f3) {
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
                print json_encode(array(
                    'error' => 'unauthorized',
                    'error_description' => $this->t('Unauthorized')
                ));
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
     */
    public function dashboard() {
        $this->blocksPage($this->t('Dashboard'), 'dashboardBlocks');
    }

    /**
     * Displays the profile page.
     */
    public function profile() {
        $this->blocksPage($this->t('My Profile'), 'profileBlocks');
    }

    /**
     * Returns the sites page.
     */
    public function apps_sync() {
        // Require HTTPS, redirect if necessary
        $this->checkHttps('redirect', true);

        $token = new SecurityToken();

        $tpl = new \Template();
        $this->f3->set('tk', $token->generate('apps', SecurityToken::OPTION_BIND_SESSION));
        $this->f3->set('title', $this->t('My Apps'));
        $this->f3->set('layout', 'my_apps.html');
        print $tpl->render('page.html');
    }

    public function apps_ajax() {
        $this->checkHttps('error', true);

        header('Content-Type: application/json');

        $token = new SecurityToken();
        if (!$this->f3->exists('GET.tk') || !$token->verify($this->f3->get('GET.tk'), 'apps')) {
            $this->f3->status(401);
            print json_encode(array(
                'error' => 'unauthorized',
                'error_description' => $this->t('Unauthorized')
            ));
            return;
        }

        $auth = AuthManager::instance();
        $user = $auth->getUser();
        $prefs = $user->clients;

        uasort($prefs, function ($a, $b) {
            return strcasecmp($a['display_name'], $b['display_name']);
        });

        $results = array();
        foreach ($prefs as $cid => $client_prefs) {
            $results[] = array_merge(array('cid' => $cid), $client_prefs);
        }
        print json_encode($results);
    }

    public function get($f3, $params) {
        $this->checkHttps('error', true);

        header('Content-Type: application/json');

        $token = new SecurityToken();
        if (!$this->f3->exists('GET.tk') || !$token->verify($this->f3->get('GET.tk'), 'apps')) {
            $this->f3->status(401);
            print json_encode(array(
                'error' => 'unauthorized',
                'error_description' => $this->t('Unauthorized')
            ));
            return;
        }

        $auth = AuthManager::instance();
        $user = $auth->getUser();
        $clients = $user->clients;
        if (!isset($clients[$params['cid']])) {
            $this->f3->status(404);
            print json_encode(array(
                'error' => 'not_found',
                'error_description' => $this->t('Not found')
            ));
            return;
        }
        
        $prefs = $clients[$params['cid']];
        $results = array(
            'first_time' => $this->f3->format('{0,date} {0,time}', $prefs['first_time']),
            'last_time' => $this->f3->format('{0,date} {0,time}', $prefs['last_time']),
            't' => array(
                'first_time_label' => $this->t('First accessed:'),
                'last_time_label' => $this->t('Last accessed:'),
                'consents_label' => $this->t('You allowed this app to:'),
            ),
        );

        $mgr = ModuleManager::instance();
        $scope_info = $mgr->invokeAll('scopes');
        $consent_info = array();
        foreach ($prefs['consents'] as $protocol => $consents) {
            if (is_array($consents)) {
                foreach ($consents as $consent) {
                    $consent_info[] = array(
                        'description' => isset($scope_info[$protocol][$consent]['description']) ? $scope_info[$protocol][$consent]['description'] : $protocol . ':' . $consent,
                        'weight' => isset($scope_info[$protocol][$consent]['weight']) ? $scope_info[$protocol][$consent]['description'] : 0
                    );
                }
            } elseif ($consents) {
                $consent_info[] = array(
                    'description' => isset($scope_info[$protocol]['description']) ? $scope_info[$protocol]['description'] : $protocol,
                    'weight' => isset($scope_info[$protocol]['weight']) ? $scope_info[$protocol]['description'] : 0
                );
            }
        }

        usort($consent_info, function ($a, $b) {
            return $this->f3->cmp($a['weight'], $b['weight']);
        });
        $results['consents'] = $consent_info;

        print json_encode($results);
    }

    public function delete($f3, $params) {
        $this->checkHttps('error', true);
        parse_str($this->f3->get('BODY'), $delete);

        header('Content-Type: application/json');

        $token = new SecurityToken();
        if (!isset($delete['tk']) || !$token->verify($delete['tk'], 'apps')) {
            $this->f3->status(401);
            print json_encode(array(
                'error' => 'unauthorized',
                'error_description' => $this->t('Unauthorized'),
            ));
            return;
        }

        $auth = AuthManager::instance();
        $user = $auth->getUser();
        $prefs = &$user->clients;
        if (!isset($prefs[$params['cid']])) {
            $this->f3->status(404);
            print json_encode(array(
                'error' => 'not_found',
                'error_description' => $this->t('Not found')
            ));
            return;
        }
        unset($prefs[$params['cid']]);
        
        $store = StoreManager::instance();
        $store->saveUser($user);

        print json_encode(array(
            'result' => 'success',
            'result_description' => $this->t('App has been deleted.')
        ));
    }

    public function navHook() {
        return array(
            array('name' => $this->t('Dashboard'), 'path' =>'my/dashboard', 'weight' => -10),
            array('name' => $this->t('My Profile'), 'path' =>'my/profile', 'weight' => -9),
            array('name' => $this->t('My Apps'), 'path' =>'my/apps', 'weight' => -8),
        );
    }

    /**
     * Returns the welcome block.
     *
     * @return array the welcome block
     */
    public function dashboardBlocksHook() {
        $auth = AuthManager::instance();
        $user = $auth->getUser();
        $tpl = new \Template();

        $blocks = array();

        $blocks[] = array(
            'id' => 'welcome',
            'title' => $this->t('Welcome'),
            'content' => $this->t('You are logged in as %identity (%uid).', array('%uid' => $user['uid'], '%identity' => $user->getDisplayName())),
            'weight' => -10
        );

        $this->f3->mset(array(
            'access_type' => $this->t('Access type'),
            'location' => $this->t('Location'),
            'time' => $this->t('Date/time'),
            'browser_label' => $this->t('Browser'),
            'app_label' => $this->t('Authorized application'),
        ));
        $blocks[] = array(
            'id' => 'activity',
            'title' => $this->t('Recent activity'),
            'content' => $tpl->render('my_activity.html', false),
            'weight' => 0
        );

        if ($this->f3->get('config.debug')) {
            $blocks[] = array(
                'id' => 'auth',
                'title' => $this->t('Authentication'),
                'content' => '<pre class="code">' . $this->f3->encode($auth->toString()) . '</pre>',
                'weight' => 10
            );

            $blocks[] = array(
                'id' => 'user',
                'title' => $this->t('User'),
                'content' => '<pre class="code">' . $this->f3->encode($user->toString()) . '</pre>',
                'weight' => 10
            );
        }
        
        return $blocks;
    }

    public function insertNav() {
        $mgr = ModuleManager::instance();

        $items = $mgr->invokeAll('nav');
        uasort($items, function($a, $b) { if ($a['weight'] == $b['weight']) { return 0; } return ($a['weight'] < $b['weight']) ? -1 : 1; });
        $this->f3->set('nav', $items);
    }

    /**
     * Generic function to display a page comprising blocks returned
     * from a hook.
     *
     * @param string $title the page title
     * @param string $hook the hook to call
     */
    protected function blocksPage($title, $hook) {
        // Require HTTPS, redirect if necessary
        $this->checkHttps('redirect', true);

        $mgr = ModuleManager::instance();

        $blocks = $mgr->invokeAll($hook);
        uasort($blocks, function($a, $b) { if ($a['weight'] == $b['weight']) { return 0; } return ($a['weight'] < $b['weight']) ? -1 : 1; });

        $tpl = new \Template();
        $this->f3->set('blocks', $blocks);
        $this->f3->set('title', $title);
        $this->f3->set('layout', 'my_blocks.html');
        print $tpl->render('page.html');        
    }
}

?>
