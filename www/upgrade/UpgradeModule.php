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
        $this->f3->set('@import url(' . $this->f3->get('base_path') . 'upgrade/upgrade.css);');
    }

    /**
     * Displays the upgrade info page.
     */
    function info() {
        $tpl = new \Template();
        
        $this->f3->set('intro',$this->t('Use this script to update your installation whenever you upgrade to a new version of SimpleID.'));
        $this->f3->set('simpleid_docs', $this->t('For more detailed information, see the <a href="!url">SimpleID documentation</a>.', array('!url' => 'http://simpleid.koinic.net/documentation/getting-started/upgrading')));
        $this->f3->set('step1', $this->t('<strong>Back up your installation</strong>. This process will change various files within your SimpleID installation and in case of emergency you may need to revert to a backup.'));
        $this->f3->set('step2', $this->t('Install your new files in the appropriate location, as described in the <a href="!url">SimpleID documentation</a>.', array('!url' => 'http://simpleid.koinic.net/documentation/getting-started/installing-simpleid')));
        $this->f3->set('click_continue', $this->t('When you have performed the steps above, click <strong>Continue</strong>.'));
        $this->f3->set('continue_button', $this->t('Continue'));

        $token = new SecurityToken();
        $this->f3->set('tk', $token->generate('upgrade_info', SecurityToken::OPTION_BIND_SESSION));
               
        $this->f3->set('title', $this->t('Upgrade'));
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
            $this->f3->set('message', $this->t('SimpleID detected a potential security attack.  Please try again.'));
            $this->info();
            return;
        }

        $tpl = new \Template();
        $cache = \Cache::instance();
        
        $cache->reset('.upgrade');

        $list = $this->getUpgradeList();
        
        if (count($list) == 0) {
            $this->f3->set('script_complete', $this->t('Your SimpleID installation is up-to-date.  This script is complete.'));
        } else {
            $rand = new Random();

            $upgid = $rand->id();
            $cache->set($upgid . '.upgrade', array('list' => $list, 'results' => ''));
            $this->f3->set('upgid', $upgid);

            $this->f3->set('tk', $token->generate('upgrade_selection', SecurityToken::OPTION_BIND_SESSION));
            
            $this->f3->set('click_continue', $this->t('Click <strong>Continue</strong> to proceed with the upgrade.'));
            $this->f3->set('continue_button', $this->t('Continue'));
        }
        
        $this->f3->set('original_version', $this->getVersion());
        $this->f3->set('this_version', SIMPLEID_VERSION);
        
        $this->f3->set('version_detected', $this->t('The version of SimpleID you are updating from has been automatically detected.'));
        $this->f3->set('original_version_label', $this->t('Original version'));
        $this->f3->set('this_version_label', $this->t('Upgrade version'));

        $this->f3->set('edit_upgrade_php', $this->t('Remember to edit upgrade.php to check <code>$upgrade_access_check</code> back to <code>FALSE</code>.'));
        
        $this->f3->set('title', $this->t('Upgrade'));
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
            $this->f3->set('message', $this->t('SimpleID detected a potential security attack.  Please try again.'));
            $this->info();
            return;
        }

        $step = $token->generate(array('upgid' => $this->f3->get('POST.upgid'), 'step' => 0), SecurityToken::OPTION_BIND_SESSION);
        $this->f3->set('step', $step);

        $this->f3->set('applying_upgrade', $this->t('Applying upgrade...'));
        $this->f3->set('title', $this->t('Upgrade'));
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
        /*if (!$this->f3->exists('GET.tk') || !$token->verify($this->f3->get('GET.tk'), 'apps')) {
            $this->f3->status(401);
            print json_encode(array(
                'error' => 'unauthorized',
                'error_description' => $this->t('Unauthorized')
            ));
            return;
        }*/
        
        $upgrade = $cache->get($upgid . '.upgrade');

        if ($upgrade === false) {

        }

        $function = $upgrade['list'][$step];
        $upgrade['results'] .= $this->f3->call($function);
        
        $next = $token->generate(array('upgid' => $upgid, 'step' => $step + 1), SecurityToken::OPTION_BIND_SESSION);
        if ($step < count($upgrade['list']) - 1) {
            print json_encode(array(
                'status' => 'next',
                'next' => $next,
                'progress' => ($step + 1) / count($upgrade['list'])
            ));
        } else {
            print json_encode(array(
                'status' => 'complete',
                'step' => $next,
                'redirect' => ''
            ));
        }
    }

    /**
     * Applies the upgrade.
     */
    function complete() {
        global $upgrade_access_check;
        
        $cache = \Cache::instance();

        $token = new SecurityToken();
        /*if (!$this->f3->exists('GET.tk') || !$token->verify($this->f3->get('GET.tk'), 'apps')) {
            $this->f3->status(401);
            print json_encode(array(
                'error' => 'unauthorized',
                'error_description' => $this->t('Unauthorized')
            ));
            return;
        }*/
        
        $upgrade = $cache->get($upgid . '.upgrade');
        $cache->reset('.upgrade');

        if ($upgrade === false) {

        }

        if (!$upgrade_access_check) {
            $this->f3->set('edit_upgrade_php', $this->t('Remember to edit upgrade.php to check <code>$upgrade_access_check</code> back to <code>TRUE</code>.'));
        }
        $this->f3->set('results', $upgrade['results']);
        
        $this->f3->set('upgrade_complete', $this->t('Your SimpleID installation has been upgraded.  Please check the results below for any errors.'));
        
        $this->f3->set('title', $this->t('Upgrade'));
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

        $this->f3->set('login_required', $this->t('Access denied. You are not authorised to access this page. Please <a href="auth/login">log in</a> as an administrator (a user whose identity file includes the line <code>administrator=1</code>).'));
        $this->f3->set('edit_upgrade_php', $this->t('If you cannot log in, you will have to edit <code>upgrade.php</code> to bypass this access check. To do this:'));
        $this->f3->set('edit_upgrade_php1', $this->t('With a text editor find the upgrade.php file.'));
        $this->f3->set('edit_upgrade_php2', $this->t('There is a line inside your upgrade.php file that says <code>$upgrade_access_check = TRUE;</code>. Change it to <code>$upgrade_access_check = FALSE;</code>.'));
        $this->f3->set('edit_upgrade_php3', $this->t('As soon as the upgrade.php script is done, you must change the file back to its original form with <code>$upgrade_access_check = TRUE;</code>.'));
        $this->f3->set('edit_upgrade_php4', $this->t('To avoid having this problem in future, remember to log in to SimpleID as an administrator before you run this script.'));
        $this->f3->set('simpleid_docs', $this->t('For more detailed information, see the <a href="!url">SimpleID documentation</a>.', array('!url' => 'http://simpleid.koinic.net/documentation/getting-started/upgrading/running-upgradephp')));
        
        $this->f3->set('title', $this->t('Access Denied'));
        $this->f3->set('layout', 'upgrade_access_denied.html');
        print $tpl->render('page.html');
        exit;
    }

    /**
     * Detects the current installed version of SimpleID
     *
     * The current installed version of SimpleID is taken from the {@link store_get() version}
     * application setting.
     *
     * @return string the detected version'
     */
    protected function getVersion() {
        $store = StoreManager::instance();
        return $store->getSetting('version') ? : SIMPLEID_VERSION;
    }

    /**
     * Sets the current version of SimpleID.
     *
     * This function sets the version application setting via {@link store_get()}.
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
     * The upgrade functions are specified by the {@link $upgrade_functions}
     * variable.  This variable is an associative array containing version numbers
     * as keys and an array of upgrade function names as values.  This function
     * merges all the upgrade function names of the version between the current
     * installed version and the upgraded version.
     *
     * @param string $version the version of SimpleID to upgrade from, calls
     * {@link upgrade_get_version()} if not specified
     * @return array an array of strings, containing the list of upgrade functions
     * to call.  The functions should be called in the same order as they appear
     * in this array
     *
     */
    protected function getUpgradeList($version = NULL) {
        $mgr = ModuleManager::instance();

        $upgrade_data = array();

        foreach ($mgr->getModules() as $name => $module) {
            $data = $mgr->invoke($name, 'upgradeList');
            if ($data != NULL) $upgrade_data = array_merge_recursive($upgrade_data, $data);
        }
        
        if ($version == NULL) $version = $this->getVersion();
        $list = array();
        
        uksort($upgrade_data, function($a, $b) {
            return -version_compare($a, $b);
        });
        
        foreach ($upgrade_data as $upgrade_version => $upgrades) {
            if (version_compare($version, $upgrade_version, '<')) {
                $list = array_merge($list, $upgrades);
            }
        }
        
        if (version_compare($version, SIMPLEID_VERSION, '<')) $list[] = 'SimpleID\Upgrade->setVersion';
        
        return $list;
    }

    public function upgradeListHook() {
        return Spyc::YAMLLoad(__DIR__ . '/upgrade.yaml');
    }
}


?>
