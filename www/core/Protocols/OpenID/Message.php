<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2024
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

namespace SimpleID\Protocols\OpenID;

use SimpleID\Util\ArrayWrapper;

/**
 * An abstract class representing an OpenID message (request
 * and response).
 *
 * This class is a subclass of {@link ArrayWrapper}.  Message parameters
 * are stored in {@link ArrayWrapper->container} and are accessed
 * using array syntax.
 */
abstract class Message extends ArrayWrapper {

    const OPENID_VERSION_2 = 2;
    const OPENID_VERSION_1_1 = 1;

    /** Constant for OpenID namespace */
    const OPENID_NS_2_0 = 'http://specs.openid.net/auth/2.0';

    /**
     * A mapping of Type URIs of OpenID extnesions to aliases provided in an OpenID
     * message.
     * 
     * @var array<string, string>
     */
    protected $extension_map = [ "http://openid.net/extensions/sreg/1.1" => "sreg" ]; // For sreg 1.0 compatibility
    
    /**
     * The version of the OpenID specification associated with
     * the current OpenID message.  This can be either {@link OPENID_VERSION_1_1}
     * or {@link OPENID_VERSION_2}.
     * 
     * @var int
     */
    protected $version;

    /**
     * Returns the OpenID version of the message
     *
     * @return int either OPENID_VERSION_2 or OPENID_VERSION_1_1
     */
    public function getVersion() {
        return $this->version;
    }

    /**
     * Filters an OpenID request to find keys specific to an extension, as specified
     * by the Type URI.
     *
     * For exmaple, if the extension has the Type URI http://example.com/ and the
     * alias example, this function will return an array of all the keys in the
     * OpenID request which starts with openid.example
     *
     * @param string $ns the Type URI of the extension
     * @return array<string, string> the filtered request, with the prefix (in the example above,
     * openid.example.) stripped in the keys.
     */
    public function getParamsForExtension($ns) {
        if (!isset($this->extension_map[$ns])) return [];
        
        $prefix = $this->getPrefix();
        $alias = $this->extension_map[$ns];
        $return = [];
        
        if (is_array($this->container)) {
            foreach ($this->container as $key => $value) {
                if ($key == $prefix . $alias) {
                    $return['#default'] = $value;
                }
                if (strpos($key, $prefix . $alias . '.') === 0) {
                    $return[substr($key, strlen($prefix . $alias . '.'))] = $value;
                }
            }
        }
        
        return $return;
    }

    /**
     * Determines whether an extension is present in an OpenID request.
     *
     * @param string $ns the Type URI of the extension
     * @return bool true if the extension is present in the request
     */
    public function hasExtension($ns) {        
        if (!isset($this->extension_map[$ns])) return false;

        $prefix = $this->getPrefix();
        $alias = $this->extension_map[$ns];
        
        if (is_array($this->container)) {
            foreach ($this->container as $key => $value) {
                if ((strpos($key, $prefix . $alias . '.') === 0) || (strpos($key, $prefix . $alias . '=') === 0)) {
                    return true;
                }
            }
        }
        
        return false;
    }

    /**
     * Obtains the mapping between namespace URIs and their aliases.
     *
     * @return array<string, string> the mapping between namespace URIs and their aliases
     */
    public function getExtensionMap() {
        return $this->extension_map;
    }

    /**
     * Creates a OpenID message for direct response.
     *
     * The response will be encoded using Key-Value Form Encoding.
     *
     * @param array<string, string> $data the data in the response
     * @return string|null the message in key-value form encoding
     * @link http://openid.net/specs/openid-authentication-1_1.html#anchor32, http://openid.net/specs/openid-authentication-2_0.html#kvform
     */
    static protected function toKeyValueForm($data) {
        $message = '';
        
        foreach ($data as $key => $value) {
            // Filter out invalid characters
            if (strpos($key, ':') !== false) return null;
            if (strpos($key, "\n") !== false) return null;
            if (strpos($value, "\n") !== false) return null;
            
            $message .= "$key:$value\n";
        }
        return $message;
    }

    /**
     * Calculates the base string from which an OpenID signature is generated,
     * given a list of fields to sign.
     * 
     * @param array<string> $signed_fields the list of fields to sign
     * @param string $prefix the prefix to be prepended to $signed_field to obtain
     * the field value - used for Requests
     * @return string the signature base string
     * @link http://openid.net/specs/openid-authentication-2_0.html#anchor11
     */
    protected function buildSignatureBaseString($signed_fields, $prefix = '') {
        $signed_data = [];
        // Remove duplicates
        $signed_fields = array_keys(array_flip($signed_fields));

        foreach ($signed_fields as $field) {
            $key = $prefix . $field;
            if (array_key_exists($key, $this->container)) {
                $signed_data[$field] = $this->container[$key];
            }
        }
        
        return self::toKeyValueForm($signed_data);
    }

    /**
     * Calculates the base string from which an OpenID signature is generated.
     *
     * Subclasses specify the list of fields to sign and calls {@link buildSignatureBaseString()}
     * 
     * @return string the signature base string
     * @link http://openid.net/specs/openid-authentication-2_0.html#anchor11
     */
    public abstract function getSignatureBaseString();

    /**
     * Returns the base string from which an OpenID signature is generated
     *
     * @return string the base string
     */
    protected abstract function getPrefix();
}
?>