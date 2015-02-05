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

namespace SimpleID\Models;

use \Base;
use \Serializable;
use SimpleID\ModuleManager;
use SimpleID\Store\Storable;
use SimpleID\Util\ArrayWrapper;
use SimpleID\Base\UserModule;

class User extends ArrayWrapper implements Serializable, Storable {

    protected $uid;

    public $auth = array();

    public $clients = array();

    public function __construct($data = array('openid' => array())) {
        parent::__construct($data);
    }

    public function loadData($data) {
        $this->container = array_replace_recursive($this->container, $data);
    }

    public function hasLocalOpenIDIdentity() {
        return isset($this->container['openid']['identity']);
    }

    public function getLocalOpenIDIdentity() {
        return ($this->hasLocalOpenIDIdentity()) ? $this->container['openid']['identity'] : null;
    }

    public function getDisplayName() {
        if (isset($this->container['userinfo']['name'])) return $this->container['userinfo']['name'];
        if (isset($this->container['userinfo']['given_name']) && isset($this->container['userinfo']['family_name']))
            return $this->container['userinfo']['given_name'] . ' ' . $this->container['userinfo']['family_name'];
        return $this->uid;
    }

    public function offsetSet($offset, $value) {
        switch ($offset) {
            case 'uid':
                $this->uid = $value;
                break;
            case 'identity':
                $this->container['openid']['identity'] = $value;
                break;
            default:
                parent::offsetSet($offset, $value);
        }
    }

    /**
     * Implementation of ArrayAccess
     */
    public function offsetExists($offset) {
        switch ($offset) {
            case 'uid':
                return true;
                break;
            case 'identity':
                return $this->hasLocalOpenIDIdentity();
                break;
            default:
                return parent::offsetExists($offset);
        }
    }


    /**
     * Implementation of ArrayAccess
     */
    public function offsetGet($offset) {
        switch ($offset) {
            case 'uid':
                return $this->uid;
                break;
            case 'identity':
                // Retained for compatibility purposes
                $mod = UserModule::instance();
                return ($this->hasLocalOpenIDIdentity()) ? $this->getLocalOpenIDIdentity() : $mod->getCanonicalURL('user/' . rawurlencode($this['uid']));
                break;
            default:
                return parent::offsetGet($offset);
        }
    }


    private function toSecureArray($hidden_value = null) {
        $mgr = ModuleManager::instance();
        $copy = new ArrayWrapper($this->container);
        $secret_paths = $mgr->invokeAll('secretUserDataPaths');
        if ($secret_paths == null) $secret_paths = array();
        $secret_paths[] = 'uid';
        foreach ($secret_paths as $path) {
            if ($hidden_value) {
                $copy->pathSet($path, $hidden_value);
            } else {
                $copy->pathUnset($path);
            }
        }
        return $copy->toArray();        
    }

    public function serialize() {
        $f3 = Base::instance();

        $result = array();
        foreach (get_object_vars($this) as $var => $value) {
            if ($var == 'container') {
                $result['container'] = $this->toSecureArray();
            } else {
                $result[$var] = $value;
            }
        }

        return $f3->serialize($result);
    }

    public function unserialize($data) {
        $f3 = Base::instance();

        $array = $f3->unserialize($data);
        foreach ($array as $var => $value) {
            $this->$var = $value;
        }
    }

    public function getStoreType() {
        return 'user';
    }

    public function getStoreID() {
        return $this->uid;
    }

    public function toString() {
        $result = array();
        foreach (get_object_vars($this) as $var => $value) {
            if ($var == 'container') {
                $result['container'] = $this->toSecureArray('[hidden]');
            } else {
                $result[$var] = $value;
            }
        }
        
        return print_r($result, true);
    }
}

?>