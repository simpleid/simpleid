<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2022
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
 *
 * Response parameters are stored *without* the `openid.` prefix.  This
 * prefix is added by the {@link render()} function when it is
 * required.
 */
class Response extends Message {

    /** Parameter for {@link $indirect_component} */
    const OPENID_RESPONSE_QUERY = 0;
    /** Parameter for {@link $indirect_component} */
    const OPENID_RESPONSE_FRAGMENT = 1;

    /** @var array an array of fields to be signed */
    private $signed_fields = [];

    /**
     * @var int the number suffix to use if an extension alias needs
     * to be automatically generated.
     */
    protected $extension_autonum = 1;

    /** @var int for indirect communication, where in the URL should the
     * response be encoded.  This can be one of OPENID_RESPONSE_QUERY
     * (always in the query string), OPENID_RESPONSE_FRAGMENT (always in the fragment) */
    protected $indirect_component = self::OPENID_RESPONSE_QUERY;

    /**
     * Creates an OpenID response.
     *
     * An OpenID response is created based on an OpenID request.  The
     * response will contain the same OpenID version, as well as the same
     * extension URI-to-alias mapping as the underlying request.
     * 
     * @param Request|array|null $request the request to which the response will
     * be made
     */
    public function __construct($request = NULL) {
        if ($request === null) return;
        if (!$request instanceof Request) $request = new Request($request);

        $this->setVersion($request->getVersion());
        $this->extension_map = $request->getExtensionMap();

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
     * Sets a field in the response
     *
     * @param string $field the field to set
     * @param string $value the value
     * @param bool|null $signed whether this field should be included in the
     * signature
     */
    public function set($field, $value, $signed = NULL) {
        $this->container[$field] = $value;

        if ($signed === null) $signed = (!in_array($field, [ 'mode', 'signed', 'sig' ]));

        if ($signed) $this->signed_fields[] = $field;
    }

    /**
     * Sets multiple fields in the response.
     *
     * @param array $data the fields and values to set
     * @param bool|null $signed whether this field should be included in the
     * signature
     */
    public function setArray($data, $signed = NULL) {
        foreach ($data as $key => $value) {
            $this->set($key, $value, $signed);
        }
    }

    /**
     * Gets the component to be used in indirect responses.
     *
     * @return int the component
     */
    public function getIndirectComponent() {
        return $this->indirect_component;
    }

    /**
     * Sets the component to be used in indirect responses.  This should
     * be either OPENID_RESPONSE_QUERY or OPENID_RESPONSE_FRAGMENT
     *
     * @param int $indirect_component the component
     */
    public function setIndirectComponent($indirect_component) {
        $this->indirect_component = $indirect_component;
    }

    /**
     * Sends an OpenID assertion response.
     *
     * The OpenID specification version 2.0 provides for the sending of assertions
     * via indirect communication.  However, future versions of the OpenID
     * specification may provide for sending of assertions via direct communication.
     *
     * @param string $indirect_url the URL to which the OpenID response is sent.  If
     * this is null, the response is sent via direct communication
     * 
     */
    public function render($indirect_url = NULL) {
        if ($indirect_url) {
            $f3 = \Base::instance();

            $f3->status(303);
            header('Location: ' . $this->toIndirectURL($indirect_url));
        } else {
            header("Content-Type: text/plain");
            print $this->toDirectMessage();
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
     * @param string $url the URL to which the OpenID response is sent.
     * @return string the encoded message
     * @since 0.8
     */
    public function toIndirectURL($url) {
        // 1. Firstly, get the query string
        $query_array = [];
        foreach ($this->container as $key => $value) $query_array['openid.' . $key] = $value;
        $query = str_replace([ '+', '%7E' ], [ '%20', '~' ], http_build_query($query_array));
        
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
        
        if (($this->getIndirectComponent() == self::OPENID_RESPONSE_QUERY) || (strpos($url, '#') === FALSE)) {
            $url .= '?' . ((isset($parts['query'])) ? $parts['query'] . '&' : '') . $query;
            if (isset($parts['fragment'])) $url .= '#' . $parts['fragment'];
        } elseif ($this->getIndirectComponent() == self::OPENID_RESPONSE_FRAGMENT) {
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
        // Remove duplicates
        $this->signed_fields = array_keys(array_flip($this->signed_fields));

        // Update signed
        $this->set('signed', implode(',', $this->signed_fields), false);

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
     * @return string|null the alias, or NULL if the Type URI does not already
     * have an alias in the current OpenID request <i>and</i> $create is false
     */
    public function getAliasForExtension($ns, $create = FALSE) {        
        if (isset($this->extension_map[$ns])) return $this->extension_map[$ns];
        if ($create !== FALSE) {
            $alias = 'e' . $this->extension_autonum;
            
            if ($create === TRUE) {
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
    static public function createError($error, $additional = [], $request = NULL) {
        $response = new Response($request);
        $response->loadData(array_merge([ 'error' => $error ], $additional));
        return $response;
    }

    /** Signed fields*/
    public function offsetSet($offset, $value): void {
        if (is_null($offset)) {
            parent::offsetSet($offset, $value);
        } else {
            $this->set($offset, $value);
        }
    }

    /** Signed fields*/
    public function offsetUnset($offset): void {
        parent::offsetUnset($offset);
        $this->signed_fields = array_diff($this->signed_fields, [ $offset ]);
    }
}

?>