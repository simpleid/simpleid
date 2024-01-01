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

namespace SimpleID\Protocols;

/**
 * Class representing a response from a HTTP request made using the
 * FatFree framework.
 */
class HTTPResponse {
    /** @var bool */
    private $isNetworkError = false;
    /** @var bool */
    private $isHTTPError = false;

    /** @var string */
    private $version;

    /** @var string|null */
    private $responseCode = null;

    /** @var string */
    private $body;

    /** @var array<string, string> */
    private $headers = [];

    /**
     * Constructs a HTTPResponse object from a response made using the
     * FatFree framework.
     * 
     * @param array<string, mixed>|false $response the response from the HTTP request
     * @see https://fatfreeframework.com/3.8/web#request
     */
    public function __construct($response) {
        if ($response === false) {
            $this->isNetworkError = true;
            $this->isHTTPError = true;
            return;
        }

        $this->body = $response['body'];
        $this->readHeaders($response['headers']);
    }

    /**
     * @param array<string> $headers
     * @return void
     */
    private function readHeaders($headers) {
        // Get the status line
        $status = array_shift($headers);

        // Parse the status line
        list($protocol, $code) = explode(' ', trim($status), 3);
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
            $this->responseCode = strval(floor(intval($code) / 100) * 100);
        }

        $this->isHTTPError = !in_array($this->responseCode, [200, 304]);

        while ($headers) {
            // Encountering another HTTP status line means there is a follow-up response
            // after a redirect. In this case drop all previous headers and start anew.
            if (preg_match('@^HTTP/\d+(\.\d+)? \d{3}@', $headers[0])) {
                $this->headers = [];
                $this->readHeaders($headers);
                return;
            }
            $field = array_shift($headers);
            list($header, $value) = explode(':', trim($field), 2);
            
            // Headers are case insensitive
            $header = self::httpCase($header);
            
            if (isset($this->headers[$header])) {
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
     * @return string the HTTP version
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