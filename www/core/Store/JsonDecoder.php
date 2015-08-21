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

namespace SimpleID\Store;

/**
 * An decoder for an extended format of JSON.
 *
 * This extended format allows for JavaScript style comments.
 */
class JsonDecoder {
    /** Internal state constant */
    const STATE_DEFAULT = 0;
    /** Internal state constant */
    const STATE_COMMENT_SINGLE = 1;
    /** Internal state constant */
    const STATE_COMMENT_MULTI = 2;
    /** Internal state constant */
    const STATE_STRING = 3;

    /** @var string source JSON after stripping comments */
    private $src;

    /** @var string JSON error */
    protected $error;

    /**
     * Decodes an extended JSON string.
     *
     * The parameters are the same as json_decode
     *
     * @link http://php.net/json_decode
     */
    public function decode($json, $assoc = false, $depth = 512, $options = 0) {
        $this->src = $this->strip($json);

        if (version_compare(phpversion(), '5.4.0', '>=')) {
            $result = json_decode($this->src, $assoc, $depth, $options);
        } elseif (version_compare(phpversion(), '5.3.0', '>=')) {
            $result = json_decode($this->src, $assoc, $depth);
        } else {
            $result = json_decode($this->src, $assoc);
        }

        $this->error = json_last_error();
        return $result;
    }

    /**
     * Returns the error in decoding the JSON string, if any.
     *
     * @return bool|string the error, or false
     */
    public function getError() {
        if ($this->error == JSON_ERROR_NONE) return false;

        switch ($this->error) {
            case JSON_ERROR_DEPTH:
                return 'Maximum stack depth exceeded';
                break;
            case JSON_ERROR_STATE_MISMATCH:
                return 'Underflow or the modes mismatch';
                break;
            case JSON_ERROR_CTRL_CHAR:
                return 'Unexpected control character found';
                break;
            case JSON_ERROR_SYNTAX:
                return 'Syntax error, malformed JSON';
                break;
            case JSON_ERROR_UTF8:
                return 'Malformed UTF-8 characters, possibly incorrectly encoded';
                break;
            default:
                return 'Other error';
                break;
        }
    }

    /**
     * Gets the JSON string after stripping comments
     *
     * @return string the JSON string
     */
    public function getJSON() {
        return $this->src;
    }

    /**
     * Strips the comments from an extended JSON string
     *
     * @param string $json the extended JSON string
     * @return string standards compliant JSON
     */
    protected function strip($json) {
        $result = '';

        $state = self::STATE_DEFAULT;

        for ($i = 0; $i < strlen($json); $i++) {
            $current = mb_substr($json, $i, 1);
            $next = ($i == strlen($json) - 1) ? '' : mb_substr($json, $i + 1, 1);
            $prev = ($i == 0) ? '' : mb_substr($json, $i - 1, 1);

            if (($state != self::STATE_COMMENT_SINGLE) && ($state != self::STATE_COMMENT_MULTI) && ($prev !== '\\') && ($current === '"')) 
                $state = ($state == self::STATE_DEFAULT) ? self::STATE_STRING : self::STATE_DEFAULT;

            if ($state == self::STATE_STRING) {
                $result .= $current;
                continue;
            }

            if (($state == self::STATE_DEFAULT) && ($current == '/') && ($next == '/')) {
                $state = self::STATE_COMMENT_SINGLE;
                $i++;
            } elseif (($state == self::STATE_COMMENT_SINGLE) && ($current == "\r") && ($next == "\n")) {
                $state = self::STATE_DEFAULT;
                $i++;
                $result .= $current . $next;
            } elseif (($state == self::STATE_COMMENT_SINGLE) && ($current == "\n")) {
                $state = self::STATE_DEFAULT;
                $result .= $current;
            } elseif (($state == self::STATE_DEFAULT) && ($current == '/') && ($next == '*')) {
                $state = self::STATE_COMMENT_MULTI;
                $i++;
                continue;
            } else if (($state == self::STATE_COMMENT_MULTI) && ($current == '*') && ($next == '/')) {
                $state = self::STATE_DEFAULT;
                $i++;
                continue;
            }

            if (($state == self::STATE_COMMENT_SINGLE) || ($state == self::STATE_COMMENT_MULTI)) continue;

            $result .= $current;
        }

        return $result;
    }
}

?>