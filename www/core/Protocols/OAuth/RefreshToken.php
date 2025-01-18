<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2025
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

/**
 * An OAuth refresh token.
 *
 * Refresh tokens are perpetual bearer tokens from which access tokens
 * can be granted.  As such, it implements the
 * {@link TokenGrantType} interface.
 *
 * To create and encode a token, use the {@link create()} static function.
 * To parse an encoded token, use the {@link decode()} static function.
 */
class RefreshToken extends Token implements TokenGrantType {
    /** Creates a refresh token */
    protected function __construct() {
        parent::__construct();
        $this->expire = null;
    }

    /**
     * Decodes an encoded token and returns an instance of this class
     * containing the decoded data.
     *
     * The decoded token can be checked for validity using the {@link isValid()}
     * and {@link hasScope()} methods.  The data can be obtained using the
     * various `get` methods.
     *
     * @param string $encoded the encoded token
     * @return RefreshToken the decoded token
     */
    static public function decode($encoded) {
        $token = new RefreshToken();
        $token->encoded = $encoded;
        $token->parse();
        return $token;
    }

    /**
     * Encodes a token from parameters and returns an instance of this class.
     *
     * The encoded token can be obtained using the {@link getEncoded()} method.
     *
     * @param Authorization $authorization the authorisation to use to create
     * this token
     * @param array<string> $scope the scope of this token - this must be a subset
     * of the scope provided in `$authorization`
     * @param TokenGrantType $source if the token is created from a previous authorisation
     * code or refresh token, the ID of those artefacts
     * @param array<string, mixed> $additional any additional data to be stored on the server for this token
     * @return RefreshToken|null 
     */
    static public function create($authorization, $scope = [], $source = NULL, $additional = []) {
        $token = new RefreshToken();
        $token->init($authorization, $scope, Token::TTL_PERPETUAL, $source, $additional);
        $token->encode();
        $token->is_parsed = true;
        return $token;
    }

    public function getGrantRef() {
        return substr($this->id, -9);
    }
}

?>