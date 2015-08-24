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
 */

namespace SimpleID\Protocols\OAuth;

use \Base;
use SimpleID\Net\HTTPResponse;
use SimpleID\Util\ArrayWrapper;

/**
 * A utility class representing a HTTP request.  This class contains
 * methods which are useful for processing OAuth-related requests.
 */
class Request extends ArrayWrapper {
    /** @var array the HTTP headers */
    protected $headers = array();

    /** @var bool whether the request prohibits user intervention */
    private $immediate = false;

    /**
     * Creates a HTTP request.
     *
     * @param array $params the request parameters
     * @param array $headers the HTTP request headers
     */
    public function __construct($params = NULL, $headers = NULL) {
        if ($params == NULL) $params = $_REQUEST;
        parent::__construct($params);

        if ($headers == NULL) {
            // Special cases
            if (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) $this->headers['authorization'] = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
            if (isset($_SERVER['PHP_AUTH_TYPE'])) {
                if (isset($_SERVER['PHP_AUTH_DIGEST'])) {
                    $this->headers['authorization'] = 'Digest ' . $_SERVER['PHP_AUTH_DIGEST'];
                } elseif (isset($_SERVER['PHP_AUTH_PW'])) {
                    $this->headers['authorization'] = 'Basic ' . base64_encode($_SERVER['PHP_AUTH_USER'] . ':' . $_SERVER['PHP_AUTH_PW']);
                }
            }

            foreach ($_SERVER as $name => $value) {
                if (substr($name, 0, 5) != 'HTTP_') continue;

                $this->headers[HTTPResponse::httpCase(strtr(substr($name, 5), '_', '-'))] = $value;
            }
        } else {
            foreach ($headers as $name => $value) $this->headers[HTTPResponse::httpCase($name)] = $value;
        }
    }

    /**
     * Returns whether the request requires that no user
     * interaction is to be made.
     *
     * @return bool true if no user interaction is to be made
     */
    public function isImmediate() {
        return $this->immediate;
    }

    /**
     * Sets whether the request requires that no user
     * interaction is to be made.
     *
     * @param bool $immediate true if no user interaction is to be made
     */
    public function setImmediate($immediate) {
        $this->immediate = $immediate;
    }

    /**
     * Returns the value of a specified header
     *
     * @param string $header the header to return
     * @return string the value of the header
     */
    public function getHeader($header) {
        return ($this->hasHeader($header)) ? $this->headers[HTTPResponse::httpCase($header)] : null;
    }

    /**
     * Returns whether a specified header exists
     *
     * @param string $header the header
     * @return bool true if the header exists
     */
    public function hasHeader($header) {
        return array_key_exists(HTTPResponse::httpCase($header), $this->headers);
    }

    /**
     * Parses and returns the request's `Authorization` header.
     *
     * This method extracts the request's `Authorization` header and returns an
     * array with the following elements:
     *
     * - `#scheme` - the authentication scheme, e.g. Basic, Bearer
     * - `#credentials` - the credentials following the scheme
     *
     * If `$parse_credentials` is true, the method will also attempt to parse
     * the credential information.  For the `Basic` scheme, the user name and
     * password will be returned in the array as `#username` and `#password`
     * respectively.  For other schemes with delimited name-value parameters,
     * those name-value pairs will be returned.
     *
     * @param bool $parse_credentials whether to parse the credential information
     * @return array the parsed `Authorization` header, or `null` if none
     * exists
     */
    public function getAuthorizationHeader($parse_credentials = false) {
        if (!$this->hasHeader('Authorization')) return null;

        $results = array();

        $header = $this->getHeader('Authorization');
        list($scheme, $credentials) = preg_split('/\s+/', $header, 2);

        $results['#scheme'] = HTTPResponse::httpCase($scheme);
        $results['#credentials'] = $credentials;

        if ($parse_credentials) {
            if ($results['#scheme'] == 'Basic') {
                list($username, $password) = explode(':', base64_decode($credentials));
                $results['#username'] = $username;
                $results['#password'] = $password;
            } else {
                $matches = array();
                preg_match_all('/([-a-zA-Z]+)=\"([^\"]+)\"/', $credentials, $matches, PREG_SET_ORDER);
                foreach ($matches as $match) $results[$match[1]] = $match[2];
            }
        }

        return $results;
    }

    /**
     * Converts a parameter consisting of space-delimited values
     * into an array of values.
     *
     * @param string $param the parameter name to check
     * @param string $delimiter a regular expression to determine
     * the delimiter between values
     * @return array an array of values, or `null` if the parameter
     * is not found
     */
    public function paramToArray($param, $delimiter = '/\s+/') {
        if (!isset($this->container[$param])) return null;
        return preg_split($delimiter, $this->container[$param]);
    }

    /**
     * Returns whether a parameter consisting of space-delimited values
     * contains a specified value.
     *
     * @param string $param the parameter name to check
     * @param string $contains the value
     * @param string $delimiter a regular expression to determine
     * the delimiter between values
     * @return bool true if the parameter contains the value, or `null` if the parameter
     * is not found
     */
    public function paramContains($param, $contains, $delimiter = '/\s+/') {
        if (!isset($this->container[$param])) return false;
        $items = $this->paramToArray($param);
        return in_array($contains, $items);
    }

    /**
     * Remove a specified value from a parameter consisting of space-delimited
     * values
     *
     * @param string $param the parameter name to check
     * @param string $contains the value to remove
     * @param string $delimiter a regular expression to determine
     * the delimiter between values
     */
    public function paramRemove($param, $value, $delimiter = '/\s+/') {
        if (!isset($this->container[$param])) return null;
        if (!$this->paramContains($param, $value)) return $this->container[$param];

        $items = preg_split($delimiter, $this->container[$param]);
        $items = array_diff($items, array($value));

        preg_match($delimiter, $this->container[$param], $matches);
        $this->container[$param] = implode($matches[0], $items);
    }
}

?>