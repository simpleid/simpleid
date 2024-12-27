/**
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2024
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

function base64urlEncode(buffer, padding) {
    // Build a binary string from u8Array
    const u8Array = new Uint8Array(buffer);
    let bstr = '';
    for (const u8 of u8Array) bstr += String.fromCharCode(u8);

    // Encode base64url
    return btoa(bstr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, padding ? '=' : '');
}

function base64urlDecode(b64u) {
    // Decode base64url from binary string
    const bstr = atob(b64u.replace(/-/g, '+').replace(/_/g, '/'));

    // Build array
    const u8Array = new Uint8Array(bstr.length);
    for (let i = 0; i < bstr.length; i++) u8Array[i] = bstr.charCodeAt(i);

    return u8Array;
}

let abortController = null;

document.addEventListener('webauthn:abort', (reason) => {
    if (abortController != null) abortController.abort(reason);
});

window.webAuthnCreatePublicKeyCredential = async function (options) {
    // Convert to PublicKeyCredentialCreationOptions
    // challenge, user.id, excludeCredentials.*.id
    options.challenge = base64urlDecode(options.challenge);
    options.user.id = base64urlDecode(options.user.id);
    if ('excludeCredentials' in options)
        options.excludeCredentials = options.excludeCredentials.map((o) => { o.id = base64urlDecode(o.id); return o; });

    abortController = new AbortController();
    const credential = await navigator.credentials.create({
        publicKey: options,
        signal: abortController.signal
    });

    // Convert from PublicKeyCredential/AuthenticatorAttestationResponse
    // rawId, response.attestationObject, response.clientDataJSON, response.authenticatorData
    // response.publicKey
    const result = {
        id: credential.id,
        rawId: base64urlEncode(credential.rawId),
        authenticatorAttachment: credential.authenticatorAttachment,
        type: credential.type,
        clientExtensionResults: credential.getClientExtensionResults(),
        response: {
            attestationObject: base64urlEncode(credential.response.attestationObject),
            clientDataJSON: base64urlEncode(credential.response.clientDataJSON),
            authenticatorData: base64urlEncode(credential.response.getAuthenticatorData()),
            publicKey: base64urlEncode(credential.response.getPublicKey()),
            publicKeyAlgorithm: credential.response.getPublicKeyAlgorithm(),
            transports: credential.response.getTransports()
        }
    };
    return result;
}

window.webAuthnGetPublicKeyCredential = async function (options) {
    // Convert from PublicKeyCredentialRequestOptions
    // publicKey.challenge, publicKey.allowCredentials.*.id
    options.publicKey.challenge = base64urlDecode(options.publicKey.challenge);
    if ('allowCredentials' in options.publicKey)
        options.publicKey.allowCredentials = options.publicKey.allowCredentials.map((o) => { o.id = base64urlDecode(o.id); return o; });

    abortController = new AbortController();
    options.signal = abortController.signal;
    const credential = await navigator.credentials.get(options);

    // Convert from PublicKeyCredential/AuthenticatorAssertionResponse
    // rawId, response.authenticatorData, response.clientDataJSON, response.signature
    // response.userHandle
    const result = {
        id: credential.id,
        rawId: base64urlEncode(credential.rawId),
        authenticatorAttachment: credential.authenticatorAttachment,
        type: credential.type,
        clientExtensionResults: credential.getClientExtensionResults(),

        response: {
            authenticatorData: base64urlEncode(credential.response.authenticatorData),
            clientDataJSON: base64urlEncode(credential.response.clientDataJSON),
            signature: base64urlEncode(credential.response.signature),
            userHandle: base64urlEncode(credential.response.userHandle),
        }
    };
    return result;    
}

document.isPublicKeyCredentialSupported = () => ('PublicKeyCredential' in window);

document.hasLocalAuthenticator = async function () {
    if (!document.isPublicKeyCredentialSupported()) return false;
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
}
