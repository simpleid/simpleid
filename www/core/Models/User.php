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
use SimpleID\Util\OpaqueIdentifier;
use SimpleID\Base\UserModule;

/**
 * Represents a SimpleID user
 */
class User extends ArrayWrapper implements Serializable, Storable {

    const ACTIVITY_LOG_SIZE = 10;

    protected $uid;

    protected $activities = array();

    public $clients = array();

    public function __construct($data = array('openid' => array())) {
        parent::__construct($data);
    }

    /**
     * Determines whether the user is an administrator
     *
     * @return bool true if the user is an administrator
     */
    public function isAdministrator() {
        return ($this->container['administrator']);
    }

    /**
     * Determines whether the user has a local OpenID identity
     *
     * @return bool true if the user has a local OpenID identity
     */
    public function hasLocalOpenIDIdentity() {
        return isset($this->container['openid']['identity']);
    }

    /**
     * Returns the user's local OpenID identity
     *
     * @return string the user's local OpenID identity
     */
    public function getLocalOpenIDIdentity() {
        return ($this->hasLocalOpenIDIdentity()) ? $this->container['openid']['identity'] : null;
    }

    public function getPairwiseIdentity($client_id) {
        $opaque = new OpaqueIdentifier();
        return 'pwid:' . $opaque->generate($this->uid, array('client_id' => $client_id));
    }

    /**
     * Returns a display name for the user.  The display name is worked
     * out based on the data available.
     *
     * @return string the display name
     */
    public function getDisplayName() {
        if (isset($this->container['userinfo']['name'])) return $this->container['userinfo']['name'];
        if (isset($this->container['userinfo']['given_name']) && isset($this->container['userinfo']['family_name']))
            return $this->container['userinfo']['given_name'] . ' ' . $this->container['userinfo']['family_name'];
        return $this->uid;
    }

    /**
     * Add an entry to the user's recent activity log.
     *
     * The recent activity log contains the most recent authentication
     * activity performed by or on behalf of the user.  This includes instances
     * where the user manually logged into SimpleID, or where a client
     * requested authentication or authorisation from the user
     *
     * @param string $id the ID of the agent creating the activity - this could
     * be the user agent ID assigned by SimpleID (in case of user logins) or
     * the client ID
     * @param array $data additional data
     */
    public function addActivity($id, $data) {
        $this->activities[$id] = $data;
        uasort($this->activities, function($a, $b) {
            if ($a['time'] == $b['time']) { return 0; } return ($a['time'] < $b['time']) ? 1 : -1;
        });
        if (count($this->activities) > self::ACTIVITY_LOG_SIZE) {
            $this->activities = array_slice($this->activities, 0, self::ACTIVITY_LOG_SIZE);
        }
    }

    /**
     * Returns the user's recent activity log.
     *
     * @return array the activity log
     */
    public function getActivities() {
        return $this->activities;
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


    public function setStoreID($id) {
        $this->uid = $id;
    }

    /**
     * Returns a string representation of the user, with sensitive
     * information removed.
     */
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