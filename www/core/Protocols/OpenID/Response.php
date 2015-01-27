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

namespace SimpleID\Protocols\OpenID;

/**
 * Class representing an OpenID response.
 */
class Response extends Message {

    /** Parameter for {@link toIndirectURL()} */
    const OPENID_RESPONSE_QUERY = 0;
    /** Parameter for {@link toIndirectURL()} */
    const OPENID_RESPONSE_FRAGMENT = 1;

    /** @var array an array of fields to be signed */
    private $signed_fields = array();

    /**
     * @var int the number suffix to use if an extension alias needs
     * to be automatically generated.
     */
    protected $extension_autonum = 1;

    /**
     * Creates an OpenID response.
     *
     * An OpenID response is created based on an OpenID request.  The
     * response will contain the same OpenID version, as well as the same
     * extension URI-to-alias mapping as the underlying request.
     * 
     * @param Request $request the request to which the response will
     * be made
     */
    public function __construct($request = NULL) {
        if ($request != NULL) {
            $this->setVersion($request->getVersion());
            $this->extension_map = $request->getExtensionMap();
        }

        foreach ($request as $key => $value) {
            if (strpos($key, 'openid.ns.') === 0) {
                $alias = substr($key, 10);
                $this->extension_map[$value] = $alias;
            }
        }
    }

    /**
     * Sets the OpenID version to be used for this response.
     *
     * If $version is {@link OPENID_VERSION_2}, the OpenID 2.0
     * namespace will be added to the response.
     *
     * @param int $version the OpenID version
     */
    public function setVersion($version) {
        if ($version == Message::OPENID_VERSION_2) {
            $this->set('ns', Message::OPENID_NS_2_0);
        } else {
            $this->offsetUnset('ns');
        }
    }

    /**
     * Set a field in the response
     *
     * @param string $field the field to set
     * @param string $value the value
     * @param bool|null $signed whether this field should be included in the
     * signature
     */
    public function set($field, $value, $signed = NULL) {
        $this->container[$field] = $value;

        if ($signed === null) $signed = (!in_array($field, array('sign', 'signature')));

        if ($signed) $signed_fields[] = $field;
    }

    public function setArray($data) {
        foreach ($data as $key => $value) {
            $this->set($key, $value);
        }
    }

    /**
     * Encodes the response in key-value format
     *
     * @return string the encoded response
     */
    public function toDirectMessage() {
        return parent::toKeyValueForm($this->container);
    }

    /**
     * Encodes the response in application/x-www-form-urlencoded format.
     *
     * @param array $message the OpenID message to encode
     * @return string the encoded message
     * @since 0.8
     */
    public function toIndirectURL($url, $component = self::OPENID_RESPONSE_QUERY) {
        // 1. Firstly, get the query string
        $query_array = array();
        foreach ($this->container as $key => $value) $query_array['openid.' . $key] = $value;
        $query = str_replace(array('+', '%7E'), array('%20', '~'), http_build_query($query_array));
        
        // 2. If there is no query string, then we just return the URL
        if (!$query) return $url;
        
        // 3. The URL may already have a query and a fragment.  If this is so, we
        //    need to slot in the new query string properly.  We disassemble and
        //    reconstruct the URL.
        $parts = parse_url($url);
        
        $url = $parts['scheme'] . '://';
        if (isset($parts['user'])) {
            $url .= $parts['user'];
            if (isset($parts['pass'])) $url .= ':' . $parts['pass'];
            $url .= '@';
        }
        $url .= $parts['host'];
        if (isset($parts['port'])) $url .= ':' . $parts['port'];
        if (isset($parts['path'])) $url .= $parts['path'];
        
        if (($component == self::OPENID_RESPONSE_QUERY) || (strpos($url, '#') === FALSE)) {
            $url .= '?' . ((isset($parts['query'])) ? $parts['query'] . '&' : '') . $query;
            if (isset($parts['fragment'])) $url .= '#' . $parts['fragment'];
        } elseif ($component == self::OPENID_RESPONSE_FRAGMENT) {
            // In theory $parts['fragment'] should be an empty string, but the
            // current draft specification does not prohibit putting other things
            // in the fragment.
            
            if (isset($parts['query'])) {
                $url .= '?' . $parts['query'] . '#' . $parts['fragment'] . '&' . $query;
            } else {
                $url .= '#' . $parts['fragment'] . '?' . $query;
            }
        }
        return $url;
    }

    /**
     * Calculates the base string from which an OpenID signature is generated.
     *
     * @return string the signature base string
     * @link http://openid.net/specs/openid-authentication-2_0.html#anchor11
     */
    public function getSignatureBaseString() {
        return $this->buildSignatureBaseString($this->signed_fields);
    }

    /**
     * Returns the OpenID alias for an extension, given a Type URI, based on the
     * alias definitions in the current OpenID request.
     *
     * @param string $ns the Type URI
     * @param bool|string $create whether to create an alias if the Type URI does not already
     * have an alias in the current OpenID request.  If this parameter is a string,
     * then the string specified is the preferred alias to be created, unless a collision
     * occurs
     * @return string the alias, or NULL if the Type URI does not already
     * have an alias in the current OpenID request <i>and</i> $create is false
     */
    public function getAliasForExtension($ns, $create = FALSE) {        
        if (isset($this->extension_map[$ns])) return $this->extension_map[$ns];
        if ($create !== FALSE) {
            if ($create === TRUE) {
                $alias = 'e' . $this->extension_autonum;
                $this->extension_autonum++;
            } elseif (is_string($create)) {
                $used_aliases = array_values($this->extension_map);
            
                $alias = $create;
                $i = 0;
            
                while (in_array($alias, $used_aliases)) {
                    $i++;
                    $alias = $create . $i;
                }
            }
            $this->extension_map[$ns] = $alias;
            return $alias;
        }
        return NULL;
    }

    /**
     * Returns the prefix to be used for extension searching.
     *
     * @return string
     */
    protected function getPrefix() {
        return '';
    }

    /**
     * Convenient function to create an error response.
     *
     * @param string $error the error message
     * @param array $additional any additional data to be sent with the error
     * message
     * @param Request $request the request
     */
    static public function createError($error, $additional = array(), $request = NULL) {
        return new Response(array_merge(array('error' => $error), $additional), $request);
    }

    /** Signed fields*/
    public function offsetSet($offset, $value) {
        if (is_null($offset)) {
            parent::offsetSet($offset, $value);
        } else {
            $this->set($offset, $value);
        }
    }

    /** Signed fields*/
    public function offsetUnset($offset) {
        parent::offsetUnset($offset);
        $this->signed_fields = array_diff($this->signed_fields, array($offset));
    }
}

?>