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
 */

namespace SimpleID\Protocols\OAuth;

/**
 * An OAuth access token.
 *
 * To create and encode a token, use the {@link create()} static function.
 * To parse an encoded token, use the {@link decode()} static function.
 */
class AccessToken extends Token {
    /** @var string */
    private $token_type = 'bearer';

    protected function __construct() {
        parent::__construct();
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
     * @return AccessToken the decoded token
     */
    static public function decode($encoded) {
        $token = new AccessToken();
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
     * @param int $expires_in the time to expiry or {@link Token::TTL_PERPETUAL}
     * @param TokenGrantType $grant if the token is created from a previous authorisation
     * code or refresh token, the ID of those artefacts
     * @param array<string, mixed> $additional any additional data to be stored on the server for this token
     * @return AccessToken|null 
     */
    static public function create($authorization, $scope = [], $expires_in = Token::TTL_PERPETUAL, $grant = NULL, $additional = []) {
        $token = new AccessToken();
        $token->init($authorization, $scope, $expires_in, $grant, $additional);
        $token->encode();
        $token->is_parsed = true;
        return $token;
    }

    /**
     * Returns the token type for this token.
     *
     * This class will always return `bearer`.  Subclasses implementing other token
     * types may return a different value.
     *
     * @return string the token type
     */
    public function getTokenType() {
        return $this->token_type;
    }
}

?>