<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2023
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

use SimpleID\Base\AuditEvent;
use SimpleID\Models\Client;
use SimpleID\Models\User;

/**
 * Event trigging when a final, non-error assertion result is returned
 * under an identity protocol.
 * 
 */
class ProtocolResultEvent extends AuditEvent implements ProtocolResult {
    /** @var int */
    protected $result;

    /**
     * Creates an event with an assertion result.
     * 
     * The result must be one of the constants defined in
     * {@link SimpleID\Protocols\ProtocolResult}.
     * 
     * @param int $result the assertion result
     * @param User $user the user the assertion result is about
     * @param Client $client the client the assertion result is provided
     * to
     */
    public function __construct(int $result, User $user, Client $client) {
        parent::__construct($user, $client);
        $this->result = $result;
    }

    /**
     * Returns the assertion result.
     * 
     * @return int the assertion result
     */
    public function getResult() {
        return $this->result;
    }

    /**
     * Returns the assertion result is positive.
     * 
     * The assertion result is positive if it is equal to
     * ProtocolResult::CHECKID_OK
     * 
     * @return bool true if the assertion is positive
     */
    public function isPositiveAssertion() {
        return ($this->result == self::CHECKID_OK);
    }
}

?>