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

namespace SimpleID\Protocols;

/**
 * An interface containing constants describing results from an
 * authentication protocol.
 */
interface ProtocolResult {
    const CHECKID_OK = 127;
    const CHECKID_RETURN_TO_SUSPECT = 3;
    const CHECKID_APPROVAL_REQUIRED = 2;
    const CHECKID_REENTER_CREDENTIALS = -1;
    const CHECKID_LOGIN_REQUIRED = -2;
    const CHECKID_IDENTITIES_NOT_MATCHING = -3;
    const CHECKID_IDENTITY_NOT_EXIST = -4;
    const CHECKID_INSUFFICIENT_TRUST = -5;
    const CHECKID_PROTOCOL_ERROR = -127;
}


?>