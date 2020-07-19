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

namespace SimpleID\Util;

/**
 * Class representing a response from a HTTP request made using the
 * FatFree framework.
 */
class HTTPResponse {

    private $isNetworkError = false;
    private $isHTTPError = false;

    private $version;
    private $responseCode = null;
    private $body;
    private $headers = [];

    /**
     * Constructs a HTTPResponse object from a response made using the
     * FatFree framework.
     * 
     * @param array $response the response from the HTTP request
     */
    public function __construct($response) {
        if ($response === false) {
            $this->isNetworkError = true;
            $this->isHTTPError = true;
            return;
        }

        $this->body = $response['body'];

        // Get the status line
        $status = array_shift($response['headers']);

        // Parse the status line
        list($protocol, $code, $reason) = explode(' ', trim($status), 3);
        $this->version = substr($protocol, strpos($protocol, '/') + 1);
        $this->responseCode = $code;

        $valid_codes = [
            100, 101,
            200, 201, 202, 203, 204, 205, 206,
            300, 301, 302, 303, 304, 305, 307,
            400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417,
            500, 501, 502, 503, 504, 505
        ];
    
        // RFC 2616 states that all unknown HTTP codes must be treated the same as the
        // base code in their class.
        if (!in_array($code, $valid_codes)) {
            $this->responseCode = floor($code / 100) * 100;
        }
        
        if (($this->responseCode != 200) && ($this->responseCode != 304)) {
            $this->isHTTPError = true;
        }

        while ($field = trim(array_shift($response['headers']))) {
            list($header, $value) = explode(':', $field, 2);
            
            // Headers are case insensitive
            $header = self::httpCase($header);
            
            if (isset($headers[$header])) {
                // RFC 2616, section 4.2: Multiple headers with the same field
                // name is the same as a concatenating all the headers in a single
                // header, separated by commas.
                $this->headers[$header] .= ','. trim($value);
            } else {
                $this->headers[$header] = trim($value);
            }
        }
    }

    /**
     * Returns whether there is a network error
     *
     * @return bool true if there is a network error
     */
    public function isNetworkError() {
        return $this->isNetworkError;
    }

    /**
     * Returns whether there is a HTTP or network error
     *
     * @return bool true if there is a HTTP or network error
     */
    public function isHTTPError() {
        return $this->isHTTPError;
    }

    /**
     * Returns the body of the HTTP response
     *
     * @return string the body of the HTTP response
     */
    public function getBody() {
        return $this->body;
    }

    /**
     * Returns the HTTP response code
     *
     * @return string the HTTP response code
     */
    public function getResponseCode() {
        return $this->responseCode;
    }

    /**
     * Returns the HTTP version
     *
     * @return float the HTTP version
     */
    public function getVersion() {
        return $this->version;
    }

    /**
     * Returns the value of a specified header
     *
     * @param string $header the header to return
     * @return string the value of the header
     */
    public function getHeader($header) {
        return $this->headers[self::httpCase($header)];
    }

    /**
     * Returns whether a specified header exists
     *
     * @param string $header the header
     * @return bool true if the header exists
     */
    public function hasHeader($header) {
        return array_key_exists(self::httpCase($header), $this->headers);
    }


    /**
     * Returns a string formatted in HTTP case.  In HTTP case, the first letter
     * after each hyphen is capitalised
     *
     * @param string $str the string to convert
     * @return string the converted string
     */
    static public function httpCase($str) {
        return implode('-', array_map('ucfirst', explode('-', strtolower($str))));
    }
}

?>