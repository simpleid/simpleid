<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021-2025
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

namespace SimpleID\Protocols\OAuth;

use SimpleID\Protocols\ProtocolResult;
use SimpleID\Protocols\ProtocolResultTrait;

/**
 * An event to processes an OAuth authorisation request to determine whether the
 * user has granted access.
 * 
 */
class OAuthAuthRequestEvent extends OAuthEvent implements ProtocolResult {
    use ProtocolResultTrait;

    public function __construct(Request $request, Response $response) {
        parent::__construct($request, $response);
    }
}

?>