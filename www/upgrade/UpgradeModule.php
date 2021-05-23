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

namespace SimpleID\Upgrade;

use \Spyc;
use Composer\Semver\Comparator;
use Composer\Semver\Semver;
use SimpleID\Module;
use SimpleID\ModuleManager;
use SimpleID\Auth\AuthManager;
use SimpleID\Crypt\Random;
use SimpleID\Store\StoreManager;
use SimpleID\Util\SecurityToken;

/**
 * SimpleID upgrade module.
 *
 * This script performs various upgrades to SimpleID's storage backend, which
 * are required for different versions of SimpleID.
 */
class UpgradeModule extends Module {
    static function routes($f3) {
        $f3->route('GET|POST /', 'SimpleID\Upgrade\UpgradeModule->info');
        $f3->route('POST /select', 'SimpleID\Upgrade\UpgradeModule->select');
        $f3->route('POST /apply [sync]', 'SimpleID\Upgrade\UpgradeModule->apply');
        $f3->route('POST /step [ajax]', 'SimpleID\Upgrade\UpgradeModule->applyStep');
        $f3->route('GET /complete', 'SimpleID\Upgrade\UpgradeModule->complete');
    }

    function beforeroute() {
        global $upgrade_access_check;

        parent::beforeroute();

        $auth = AuthManager::instance();
        if ($upgrade_access_check) {
            if (!$auth->isLoggedIn() || !$auth->getUser()->isAdministrator())
                $this->accessDenied();
        }

        $this->f3->set('upgrade_access_check', $upgrade_access_check);
        $this->f3->set('css', '@import url(' . $this->f3->get('base_path') . 'upgrade/upgrade.css);');
    }

    /**
     * Displays the upgrade info page.
     */
    function info() {
        $tpl = new \Template();
        
        $this->f3->set('upgrade_url', 'http://simpleid.org/documentation/getting-started/upgrading');

        $token = new SecurityToken();
        $this->f3->set('tk', $token->generate('upgrade_info', SecurityToken::OPTION_BIND_SESSION));
               
        $this->f3->set('title', $this->f3->get('intl.upgrade.upgrade_title'));
        $this->f3->set('page_class', 'dialog-page');
        $this->f3->set('layout', 'upgrade_info.html');
        
        print $tpl->render('page.html');
    }

    /**
     * Detects the current installed version of SimpleID, selects the individual upgrade
     * functions applicable to this upgrade and displays the upgrade
     * selection page.
     */
    function select() {
        global $upgrade_access_check;

        $token = new SecurityToken();
        if (($this->f3->exists('POST.tk') === false) || !$token->verify($this->f3->get('POST.tk'), 'upgrade_info')) {
            $this->f3->set('message', $this->f3->get('intl.common.invalid_tk'));
            $this->info();
            return;
        }

        $tpl = new \Template();
        $cache = \Cache::instance();
        
        $cache->reset('.upgrade');

        $list = $this->getUpgradeList();
        
        if (count($list) != 0)
            $rand = new Random();

            $upgid = $rand->id();
            $cache->set($upgid . '.upgrade', [ 'list' => $list, 'results' => '' ]);
            $this->f3->set('upgid', $upgid);

            $this->f3->set('tk', $token->generate('upgrade_selection', SecurityToken::OPTION_BIND_SESSION));
        }
        
        $this->f3->set('original_version', $this->getVersion());
        $this->f3->set('this_version', SIMPLEID_VERSION);
        
        $this->f3->set('title', $this->f3->get('intl.upgrade.upgrade_title'));
        $this->f3->set('page_class', 'dialog-page');
        $this->f3->set('layout', 'upgrade_selection.html');
        
        print $tpl->render('page.html');
    }

    /**
     * Applies the upgrade.
     */
    function apply() {
        $token = new SecurityToken();
        if (($this->f3->exists('POST.tk') === false) || !$token->verify($this->f3->get('POST.tk'), 'upgrade_selection')) {
            $this->f3->set('message', $this->f3->get('intl.common.invalid_tk'));
            $this->info();
            return;
        }

        $step = $token->generate([ 'upgid' => $this->f3->get('POST.upgid'), 'step' => 0 ], SecurityToken::OPTION_BIND_SESSION);
        $this->f3->set('step', $step);

        $this->f3->set('title', $this->f3->get('intl.upgrade.upgrade_title'));
        $this->f3->set('page_class', 'dialog-page');
        $this->f3->set('layout', 'upgrade_apply.html');
        
        print $tpl->render('page.html');
    }

    /**
     * Applies a single step of the upgrade.
     */
    function applyStep() {
        header('Content-Type: application/json');

        $cache = \Cache::instance();

        $token = new SecurityToken();
        if (!$this->f3->exists('POST.step')) {
            $this->f3->status(401);
            print json_encode([
                'status' => 'error',
                'error' => 'unauthorized',
                'error_description' => $this->f3->get('intl.common.unauthorized')
            ]);
            return;
        }
        
        $payload = $token->getPayload($this->f3->get('POST.step'));
        if ($payload == null) {
            $this->f3->status(401);
            print json_encode([
                'status' => 'error',
                'error' => 'unauthorized',
                'error_description' => $this->f3->get('intl.common.unauthorized')
            ]);
            return;
        }

        $upgid = $payload['upgid'];
        $step = $payload['step'];

        $upgrade = $cache->get($payload['upgid'] . '.upgrade');

        if ($upgrade === false) {
            $this->f3->status(500);
            print json_encode([
                'status' => 'error',
                'error' => 'upgrade_error',
                'error_description' => $this->f3->get('intl.upgrade.upgrade_not_found')
            ]);
            return;
        }

        $function = $upgrade['list'][$step];
        $upgrade['results'] .= $this->f3->call($function);
        
        $next = $token->generate([ 'upgid' => $upgid, 'step' => $step + 1 ], SecurityToken::OPTION_BIND_SESSION);
        if ($step < count($upgrade['list']) - 1) {
            print json_encode([
                'status' => 'next',
                'next' => $next,
                'progress' => $this->f3->format('{0,number,percent}', ($step + 1) / count($upgrade['list']))
            ]);
        } else {
            print json_encode([
                'status' => 'complete',
                'redirect' => 'complete?tk=' . rawurlencode($next)
            ]);
        }
    }

    /**
     * Applies the upgrade.
     */
    function complete() {
        global $upgrade_access_check;
        
        $cache = \Cache::instance();

        $token = new SecurityToken();
        if (!$this->f3->exists('GET.tk')) {
            $this->f3->status(401);
            $this->fatalError($this->f3->get('intl.common.invalid_tk'));
            return;
        }

        $payload = $token->getPayload($this->f3->get('POST.step'));
        if ($payload == null) {
            $this->f3->status(401);
            $this->fatalError($this->f3->get('intl.common.invalid_tk'));
            return;
        }

        $upgid = $payload['upgid'];
        
        $upgrade = $cache->get($upgid . '.upgrade');
        $cache->reset('.upgrade');

        if ($upgrade === false) {
            $this->f3->status(500);
            $this->fatalError($this->f3->get('intl.upgrade.upgrade_not_found'));
        }

        $this->f3->set('results', $upgrade['results']);
                
        $this->f3->set('title', $this->f3->get('intl.upgrade.upgrade_title'));
        $this->f3->set('page_class', 'dialog-page');
        $this->f3->set('layout', 'upgrade_results.html');
        
        print $tpl->render('page.html');
    }

    /**
     * Displays a page notifying the user that he or she does not have permission to
     * run the upgrade script.
     */
    protected function accessDenied() {
        $tpl = new \Template();

        $this->f3->set('upgrade_url', 'http://simpleid.org/documentation/getting-started/upgrading/running-upgradephp'));
        
        $this->f3->set('title', $this->f3->get('intl.common.access_denied'));
        $this->f3->set('layout', 'upgrade_access_denied.html');
        print $tpl->render('page.html');
        exit;
    }

    /**
     * Detects the current installed version of SimpleID
     *
     * The current installed version of SimpleID is taken from the `version`
     * application setting.
     *
     * @return string the detected version
     */
    protected function getVersion() {
        $store = StoreManager::instance();
        return $store->getSetting('version') ? : SIMPLEID_VERSION;
    }

    /**
     * Sets the current version of SimpleID.
     *
     * This function sets the version application setting via {@link \SimpleID\Store\StoreManager::setSetting()}.
     * A specific version can be specified, or it can be taken from {@link SIMPLEID_VERSION}.
     *
     * @param string $version the version to set
     */
    public function setVersion($version = NULL) {
        $store = StoreManager::instance();
        if ($version == NULL) $version = SIMPLEID_VERSION;
        $store->setSetting('version', $version);
    }

    /**
     * Selects the upgrade functions applicable for this upgrade.
     *
     * The upgrade functions are specified by the `upgradeList`
     * hook.  This variable is an associative array containing version numbers
     * as keys and an array of upgrade function names as values.  This function
     * merges all the upgrade function names of the version between the current
     * installed version and the upgraded version.
     *
     * @param string $version the version of SimpleID to upgrade from, calls
     * {@link getVersion()} if not specified
     * @return array an array of strings, containing the list of upgrade functions
     * to call.  The functions should be called in the same order as they appear
     * in this array
     * @see SimpleID\API\ModuleHooks::upgradeListHook()
     */
    protected function getUpgradeList($version = NULL) {
        $mgr = ModuleManager::instance();

        $upgrade_data = [];

        foreach ($mgr->getModules() as $name => $module) {
            $data = $mgr->invoke($name, 'upgradeList');
            if ($data != NULL) $upgrade_data = array_merge_recursive($upgrade_data, $data);
        }
        
        if ($version == NULL) $version = $this->getVersion();
        $list = [];
        
        // Sorts versions from newest to oldest
        $versions = array_keys($upgrade_data);
        $versions = Semver::rsort($versions);
        
        foreach ($versions as $upgrade_version) {
            if (Comparator::lessThan($version, $upgrade_version)) {
                $list = array_merge($list, $upgrade_data[$upgrade_version]);
            }
        }
        
        if (Comparator::lessThan($version, SIMPLEID_VERSION)) $list[] = 'SimpleID\Upgrade->setVersion';
        
        return $list;
    }

    public function upgradeListHook() {
        return Spyc::YAMLLoad(__DIR__ . '/upgrade.yml');
    }
}


?>
