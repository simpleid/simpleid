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

/**
 * Manages SimpleID modules.
 *
 * This is a singleton class which is used to load modules specified in
 * the configuration file.  This class also provides functionality for
 * calling hooks.
 */
class ModuleManager extends Prefab {
    /** @var array array of all loaded modules */
    private $modules = [];

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
        
        $info = $this->getModuleInfo($name);
        $module = new $name();
        $this->modules[$name] = $module;
        
        if (isset($info['asset_domain'])) {
            $this->f3->set('UI', $this->f3->get('UI') . ';' . $info['asset_dir']);
            $this->f3->set('LOCALES', $this->f3->get('LOCALES') . ';' . $info['asset_dir']);
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
     * Initialises the loaded modules.
     */
    public function initModules() {
        $listeners = \Listeners::instance();

        foreach ($this->modules as $name => $module) {
            if (method_exists($name, 'init')) {
                $this->logger->log(LogLevel::DEBUG, 'SimpleID\ModuleManager->initModules: ' . $name);
                call_user_func([ $name, 'init' ], $this->f3);
            }
            $listeners->map($module);
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
            return call_user_func_array([ $this->modules[$name], $function ], $args);
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
        $return = [];

        foreach ($this->modules as $name => $module) {
            if (method_exists($module, $function)) {
                $this->logger->log(LogLevel::DEBUG, 'SimpleID\ModuleManager->invokeAll: ' . $name . '->' . $function);
                $result = call_user_func_array([ $module, $function ], $args);
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
        $return = [];

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

    /**
     * Retrieves information on a SimpleID module
     *
     * @param string $name the fully qualified class name of the module
     */
    public function getModuleInfo($class) {
        $loader = $this->f3->get('class_loader');
        $root_dir = strtr(dirname(__DIR__), '\\', '/'); // Cross-platform way of getting a parent directory

        $results = [];

        $class_file = $loader->findFile($class);
        $class_dir = strtr(dirname($class_file), '\\', '/');

        if (strncmp($root_dir, $class_dir, strlen($root_dir)) === 0) {
            $relative_dir = substr($class_dir, strlen($root_dir) + 1);
            list ($base_dir, $module_dir, $dummy) = explode('/', $relative_dir, 3);

            switch ($base_dir) {
                case 'core':
                    break;
                case 'upgrade':
                    $results['asset_dir'] = $base_dir . '/';
                    $results['asset_domain'] = $base_dir;
                    break;
                case 'site':
                    $results['asset_dir'] = $base_dir . '/' . $module_dir . '/';
                    $results['asset_domain'] = $module_dir;
                    break;
            }
        }

        $results['file'] = $class_file;
        $results['dir'] = $class_dir;

        return $results;
    }
}

?>