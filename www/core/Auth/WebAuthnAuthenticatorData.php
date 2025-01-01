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
 * 
 */

namespace SimpleID\Auth;

use \InvalidArgumentException;
use SimpleJWT\Util\Util as SimpleJWTUtil;

/**
 * 
 */
class WebAuthnAuthenticatorData {
    /**
     * The hash of the RpID, in base64url encoding
     * 
     * @var string
     */
    protected $rpIdHash;

    /**
     * User present flag.
     * 
     * @var bool
     */
    protected $userPresentFlag;

    /**
     * User verified flag.
     * 
     * @var bool
     */
    protected $userVerifiedFlag;

    /**
     * Backup eligibility flag.
     * 
     * @var bool
     */
    protected $backupEligibleFlag;

    /**
     * Backup state flag.
     * 
     * @var bool
     */
    protected $backupStateFlag;

    /**
     * Flag to indicate whether attestation data exists.
     * 
     * @var bool
     */
    protected $attestedDataIncludedFlag;

    /**
     * Flag to indicate whether extension data exists.
     * 
     * @var bool
     */
    protected $extensionDataIncludedFlag;

    /**
     * Value of signature counter.
     * 
     * @var int $signCount
     */
    protected $signCount;

    /**
     * The AAGUID in hex format (e.g. 00000000-0000-0000-0000-000000000000)
     * 
     * @var ?string $aaguid
     */
    protected $aaguid;

    function __construct(string $binary) {
        if (strlen($binary) < 37)
            throw new InvalidArgumentException('Unexpected length of authenticatorData');

        // https://www.w3.org/TR/webauthn/#sec-authenticator-data
        // rpIdHash
        $this->rpIdHash = SimpleJWTUtil::base64url_encode(substr($binary, 0, 32));

        // flags
        $flags = ord($binary[32]);
        $this->userPresentFlag = (($flags & 1) > 0);
        $this->userVerifiedFlag = (($flags & 4) > 0);
        $this->backupEligibleFlag = (($flags & 8) > 0);
        $this->backupStateFlag = (($flags & 16) > 0);
        $this->attestedDataIncludedFlag = (($flags & 64) > 0);
        $this->extensionDataIncludedFlag = (($flags & 128) > 0);

        // signCount
        $signCount = unpack('N', substr($binary, 33, 4));
        if ($signCount === false) throw new InvalidArgumentException('Invalid signCount');
        $this->signCount = $signCount[1];

        // attestationData
        $pos = 37;
        if ($this->attestedDataIncludedFlag) {
            if (strlen($binary) < 56)
                throw new InvalidArgumentException('Unexpected length of authenticatorData with attestationData');

            $hex = bin2hex(substr($binary, 37, 16));
            $this->aaguid = sprintf('%08s-%04s-%04s-%04s-%012s', substr($hex, 0, 8), substr($hex, 8, 4), substr($hex, 12, 4), substr($hex, 16, 4), substr($hex, 20));
        }
    }

    /**
     * Returns the value of the RP ID hash as a base64url encoded string
     * 
     * @return string the RP ID hash
     */
    public function getRpIdHash(): string {
        return $this->rpIdHash;
    }

    /**
     * Returns the value of the signature counter.
     * 
     * @return int the value of the signature counter
     */
    public function getSignCount(): int {
        return $this->signCount;
    }

    /**
     * Returns the AAGUID of the authenticator.
     * 
     * The value is formatted in lowercase hex format
     * (e.g. 00000000-0000-0000-0000-000000000000)
     * 
     * @return ?string the AAGUID, or null if the AAGUID is not
     * included
     */
    public function getAAGUID(): ?string {
        return $this->aaguid;
    }

    /**
     * Returns whether the user was present.  If true, the authenticator has 
     * performed a Test of User Presence (TUP), such as touching a button on
     * the authenticator.
     * 
     * @return bool true if the user was present
     */
    public function isUserPresent(): bool {
        return $this->userPresentFlag;
    }

    /**
     * Returns whether the user was verified.  If true, authenticator has
     * performed verification using e.g. PIN or biometrics
     * 
     * @return bool true if the user was verified
     */
    public function isUserVerified(): bool {
        return $this->userVerifiedFlag;
    }

    /**
     * Returns whether the credentials stored in the authenticator can
     * be backed up, e.g. to the cloud.  This allows the credentials
     * to be used across multiple devices.
     * 
     * @return bool true if the authenticator can be backed up
     */
    public function isBackupEligible(): bool {
        return $this->backupEligibleFlag;
    }

    /**
     * Returns whether the credentials stored in the authenticator has
     * be backed up.
     * 
     * This is only meaningful if `isBackupEligible()` returns true
     * 
     * @return bool true if the authenticator can be backed up
     */
    public function isBackedUp(): bool {
        return $this->backupStateFlag;
    }
}
?>
