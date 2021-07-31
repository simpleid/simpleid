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

/**
 * SimpleID upgrade script.
 *
 * This script performs various upgrades to SimpleID's storage backend, which
 * are required for different versions of SimpleID.
 *
 * @package simpleid
 * @since 0.7
 * @filesource
 */

/**
 * Access control for this script.
 *
 * If you are upgrading your SimpleID installation using the upgrade.php script,
 * and you are not logged in as an administrator, you will need to modify the access
 * check statement below.
 *
 * Change the TRUE to a FALSE to disable the access
 * check. After finishing the upgrade, be sure to open this file again
 * and change the FALSE back to a TRUE.
 *
 * @global bool $upgrade_access_check
 */
$upgrade_access_check = TRUE;

/* ----- Do not modify anything following this line ------------------------- */

chdir('..');

require_once "bootstrap.inc.php";

$f3->set('base_path', $f3->get('base_path') . '../');

// Fix up the route URI 
$f3->set('URI', preg_replace('!/index\\.php!', '', $f3->get('URI')));

$mgr = SimpleID\ModuleManager::instance();
$store = SimpleID\Store\StoreManager::instance();

$upgrade_modules = [
    'SimpleID\Upgrade\UpgradeModule',
    'SimpleID\Store\DefaultStoreModule',
];
foreach ($upgrade_modules as $module) $mgr->loadModule($module);

$config = $f3->get('config');
foreach ($config['modules'] as $module) $mgr->loadModule($module);

$store->checkStores();
SimpleID\Upgrade\UpgradeModule::init($f3); // We call this directly instead of initModules();

$f3->run();
?>
