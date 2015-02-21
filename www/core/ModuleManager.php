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

namespace SimpleID;

use \Prefab;
use \Base;
use Psr\Log\LogLevel;
use SimpleID\Util\LocaleManager;

/**
 * Manages SimpleID modules.
 *
 * This is a singleton class which is used to load modules specified in
 * the configuration file.  This class also provides functionality for
 * calling hooks.
 *
 * @since 2.0
 */
class ModuleManager extends Prefab {
    /** @var array array of all loaded modules */
    private $modules = array();

    private $f3;
    private $logger;

    function __construct() {
        $this->f3 = Base::instance();
        $this->logger = $this->f3->get('logger');
    }

    /**
     * Loads a module.
     *
     * @param string $name the fully qualified class name of the module to load
     */
    public function loadModule($name) {
        $this->logger->log(LogLevel::INFO, 'SimpleID\ModuleManager->loadModule: ' . $name);

        if (isset($this->modules[$name])) return;
        
        $info = autoload_get_module_info($name);
        $module = new $name();
        $this->modules[$name] = $module;
        
        if (isset($info['site'])) {
            $this->f3->set('UI', $f3->get('UI') . PATH_SEPARATOR . $info['dir']);

            $locale = LocaleManager::instance();
            $locale->addDomain($info['site'], $info['dir']);
        }
    }

    /**
     * Returns whether a specified module is loaded.
     *
     * @param string $name the fully qualified class name of the module
     * @return bool true if the module is loaded
     */
    public function isModuleLoaded($name) {
        return isset($this->modules[$name]);
    }

    /**
     * Returns a specified loaded module.
     *
     * @param string $name the fully qualified class name of the module to return
     * @return Module the module
     */
    public function getModule($name) {
        return $this->modules[$name];
    }

    /**
     * Returns a list of loaded modules
     *
     * @return array an array of fully qualified class names of the loaded
     * modules
     */
    public function getModules() {
        return array_keys($this->modules);
    }

    /**
     * Initialises the routes made available by the loaded modules.
     */
    public function initRoutes() {
        foreach ($this->modules as $name => $module) {
            if (method_exists($name, 'routes')) {
                $this->logger->log(LogLevel::DEBUG, 'SimpleID\ModuleManager->initRoutes: ' . $name);
                call_user_func(array($name, 'routes'), $this->f3);
            }
        }
    }

    /**
     * Invokes a hook in a specified module.
     *
     * @param string $name the module to call
     * @param string $hook the name of the hook to call
     * @param mixed $args the arguments to the hook
     * @return mixed the return value from the hook
     */
    public function invoke() {
        $args = func_get_args();
        $name = array_shift($args);
        $function = array_shift($args) . 'Hook';

        if (method_exists($this->modules[$name], $function)) {
            $this->logger->log(LogLevel::DEBUG, 'SimpleID\ModuleManager->invoke: ' . $name . '->' . $function);
            return call_user_func_array(array($this->modules[$name], $function), $args);
        }
    }

    /**
     * Invokes a hook in all the loaded modules.
     *
     * @param string $hook the name of the hook to call
     * @param mixed $args the arguments to the hook
     * @return array the return values from the hook
     */
    public function invokeAll() {
        $args = func_get_args();
        $function = array_shift($args) . 'Hook';
        $return = array();

        foreach ($this->modules as $name => $module) {
            if (method_exists($module, $function)) {
                $this->logger->log(LogLevel::DEBUG, 'SimpleID\ModuleManager->invokeAll: ' . $name . '->' . $function);
                $result = call_user_func_array(array($module, $function), $args);
                if (isset($result) && is_array($result)) {
                    $return = array_merge($return, $result);
                } elseif (isset($result)) {
                    $return[] = $result;
                }
            }
        }
        
        return $return;
    }

    /**
     * Invokes a hook in a specified module by reference.
     *
     * @param string $name the module to call
     * @param string $hook the name of the hook to call
     * @param mixed &$data the data that is passed by reference
     * @return mixed the return value from the hook
     */
    public function invokeRef($name, $hook, &$data) {
        $function = $hook . 'Hook';

        if (method_exists($this->modules[$name], $function)) {
            $this->logger->log(LogLevel::DEBUG, 'SimpleID\ModuleManager->invokeRef: ' . $name . '->' . $function);
            return $this->modules[$name]->$function($data);
        }
    }

    /**
     * Invokes a hook in all the loaded modules by reference.
     *
     * @param string $hook the name of the hook to call
     * @param mixed &$data the data that is passed by reference
     * @return array the return values from the hook
     */
    public function invokeRefAll($hook, &$data) {
        $function = $hook . 'Hook';
        $return = array();

        foreach ($this->modules as $name => $module) {
            if (method_exists($module, $function)) {
                $this->logger->log(LogLevel::DEBUG, 'SimpleID\ModuleManager->invokeRefAll: ' . $name . '->' . $function);
                $result = $module->$function($data);
                if (isset($result) && is_array($result)) {
                    $return = array_merge($return, $result);
                } elseif (isset($result)) {
                    $return[] = $result;
                }
            }
        }
        
        return $return;
    }
}

?>