// Copyright 2019 SoloKeys Developers
// Copyright 2022 Nitrokey GmbH
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// Parts of the implementation taken from:
// https://github.com/solokeys/solo-webupdate

import {CMD, command_codes, ctap_error_codes, VERBOSE} from "./constants";
// import {webauthn_supported} from "./platform";

interface U2fResponse {
    authenticatorData: any;
    signature: any;
}

interface Credential2 extends Credential {
    response?: U2fResponse;
}


/**
 * Encode Webcrypt request into KEYHANDLE, sent over Webauthn. Data gets back in the SIGNATURE field.
 * @param cmd
 * @param data
 */
function encode_ctaphid_request_as_keyhandle(cmd: number, data: Uint8Array) {
    if (VERBOSE) console.log('ctaphid REQUEST CMD', cmd, '(', command_codes[cmd], ')', data);
    data = data || new Uint8Array(16).fill(64);

    const offset = 5;

    if (offset + data.length > 255) {
        throw new Error("Max size exceeded");
    }

    const array = new Uint8Array(offset + data.length);

    array[0] = cmd & 0xff;

    // Set magic bytes, after which the command is recognized by the device as Webcrypt's
    array[1] = 0x8C;  // 140
    array[2] = 0x27;  //  39
    array[3] = 0x90;  // 144
    array[4] = 0xf6;  // 246

    array.set(data, offset);

    if (VERBOSE) console.log('ctaphid FORMATTED REQUEST:', array);
    return array;
}


function decode_ctaphid_response_from_signature(response: U2fResponse) {
    // https://fidoalliance.org/specs/fido-v2.0-rd-20170927/fido-client-to-authenticator-protocol-v2.0-rd-20170927.html#using-the-ctap2-authenticatorgetassertion-command-with-ctap1-u2f-authenticators<Paste>
    //
    // compared to `parse_device_response`, the data is encoded a little differently here
    //
    // attestation.response.authenticatorData
    //
    // first 32 bytes: SHA-256 hash of the rp.id
    // 1 byte: zeroth bit = user presence set in U2F response (always 1)
    // last 4 bytes: signature counter (32 bit big-endian)
    //
    // attestation.response.signature
    // signature data (bytes 5-end of U2F response

    const signature_count = (
        new DataView(
            response.authenticatorData.slice(33, 37)
        )
    ).getUint32(0, false); // get count as 32 bit BE integer

    const signature = new Uint8Array(response.signature);
    let data = null;

    let error_code = null;
    if (signature.length>0){
        error_code = signature[0]; // CMD_WRITE only
        if (error_code == 0) {
            data = signature.slice(1, signature.length);
        }
    }

    return {
        count: signature_count,
        // status: ctap_error_codes[error_code],
        status: "error_code",
        status_code: error_code,
        data: data,
        signature: signature,
    };
}


export async function ctaphid_via_webauthn(cmd: CMD, data: Uint8Array, timeout: number): Promise<any> {
    // if a token does not support CTAP2, WebAuthn re-encodes as CTAP1/U2F:
    // https://fidoalliance.org/specs/fido-v2.0-rd-20170927/fido-client-to-authenticator-protocol-v2.0-rd-20170927.html#interoperating-with-ctap1-u2f-authenticators
    //
    // problem: the popup to press button flashes up briefly :(

    const keyhandle = encode_ctaphid_request_as_keyhandle(cmd, data);
//   const challenge = window.crypto.getRandomValues(new Uint8Array(32));
    const challenge = new Uint8Array(32).fill(69);


    const request_options: PublicKeyCredentialRequestOptions = {
        challenge: challenge,
        allowCredentials: [{
            id: keyhandle,
            type: 'public-key',
        }],
        timeout: timeout,
        userVerification: "discouraged",
    }

    // if (!webauthn_supported())
    //     throw "Webauthn is not supported";

    try {
        const result = await navigator.credentials.get({
            publicKey: request_options
        });
        const assertion: Credential2 | null = result;
        if (VERBOSE) console.log("ctaphid GOT ASSERTION", assertion);
        if (!assertion) throw new Error("Empty assertion");
        if (!assertion.response) throw new Error("Empty assertion response");

        if (VERBOSE) console.log("ctaphid RESPONSE", assertion.response);
        const response = decode_ctaphid_response_from_signature(assertion.response!);
        if (VERBOSE) console.log("ctaphid RESPONSE decoded:", response);
        return response;
    } catch (error) {
        console.log(`ctaphid ERROR CALLING: ${cmd}/${command_codes[cmd]}`); //, data
        console.log("ctaphid THE ERROR:", error);
        throw error;
        return Promise.resolve();  // error;
    }

}


