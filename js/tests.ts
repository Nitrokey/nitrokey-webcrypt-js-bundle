// Copyright 2022 Nitrokey GmbH
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

import {
    CommandChangePinParams, CommandDecryptParams,
    CommandGenerateKeyFromDataParams, CommandInitializeSeedParams,
    CommandLoginParams, CommandReadResidentKeyPublicParams, CommandRestoreFromSeedParams, CommandSetConfigurationParams,
    CommandSetPinParams,
    CommandSignParams, CommandWriteResidentKeyParams,
    Webcrypt_ChangePin, Webcrypt_Decrypt, WEBCRYPT_ENCRYPT,
    Webcrypt_FactoryReset,
    Webcrypt_GenerateKey,
    Webcrypt_GenerateKeyFromData,
    Webcrypt_GenerateResidentKey, Webcrypt_GetConfiguration, Webcrypt_InitializeSeed,
    Webcrypt_Login,
    Webcrypt_Logout,
    Webcrypt_ReadResidentKeyPublic, Webcrypt_RestoreFromSeed, Webcrypt_SetConfiguration,
    Webcrypt_SetPin,
    Webcrypt_Sign,
    Webcrypt_Status, Webcrypt_WriteResidentKey,
    WebcryptData
} from "./webcrypt";
import {Dictionary, ProgressCallback, StatusCallback} from "./types";
import {
    agree_on_key, buffer_to_uint8, byteToHexString, calculate_hmac, dict_hexval, ecdsa_to_ecdh,
    encode_text, encrypt_aes,
    export_key, flatten,
    generate_key_ecc,
    get_hash, getBinaryStr,
    hexStringToByte,
    import_key, number_to_short, pkcs7_pad_16, remove_pkcs7_pad_16,
    TEST, uint8ToUint16
} from "./helpers";

class TestRecord {
    public fn: Function;

    constructor(fn: Function) {
        this.fn = fn;
    }
}

//
// export async function WebcryptTestsList(logfn: StatusCallback): Promise<void> {
//     let context = {};
//     const tests = [
//         new TestRecord(ctx => Webcrypt_Status(logfn)),
//         new TestRecord(ctx => { Webcrypt_GenerateKey(logfn) }),
//         new TestRecord(ctx => Webcrypt_GenerateKey(logfn)),
//         new TestRecord(ctx => Webcrypt_GenerateKey(logfn)),
//     ];
//
//     for (let t of tests){
//         const data = await t.fn(context);
//         await logfn(JSON.stringify(data));
//     }
//
// }

export async function should_throw(logfn:Function, fn:Function, expected_str:string ){
    logfn(`Following call should throw ${expected_str}`);
    try {
        await fn();
        TEST(false, "This should fail");
    } catch (e: any) {
        if (e.toString().indexOf("TEST FAIL") !== -1) {
            logfn(`--- FAIL - Expected error not encountered: ${e}`);
            throw e;
        }
        if (e.toString().indexOf(expected_str) === -1) {
            logfn(`--- FAIL - Different error encountered: ${e}`);
            throw e;
        }
        //as expected, continue
        logfn(`+++ PASS - Expected error encountered: ${e}`);
    }
}

export async function WebcryptTests(logfn: StatusCallback, progressfn: ProgressCallback): Promise<void> {
    let progress = 0;
    const max_progress = 23;
    await Webcrypt_FactoryReset(logfn);
    await progressfn(progress++, max_progress);

    let status_res = await Webcrypt_Status(logfn);
    await logfn(JSON.stringify(status_res));
    TEST(!status_res.UNLOCKED, "session should be closed", logfn);
    await progressfn(progress++, max_progress);

    const DEFAULT_PIN = "12345678";
    const NEWPIN = "newpin";
    await Webcrypt_SetPin(logfn, new CommandSetPinParams(DEFAULT_PIN));
    await progressfn(progress++, max_progress);

    await Webcrypt_ChangePin(logfn, new CommandChangePinParams(DEFAULT_PIN, NEWPIN))
    await progressfn(progress++, max_progress);

    await should_throw(logfn, async () => {
        await Webcrypt_Login(logfn, new CommandLoginParams(DEFAULT_PIN));
    }, "ERR_INVALID_PIN");
    await progressfn(progress++, max_progress);

    await Webcrypt_ChangePin(logfn, new CommandChangePinParams(NEWPIN, DEFAULT_PIN))
    await progressfn(progress++, max_progress);
    await Webcrypt_Login(logfn, new CommandLoginParams(DEFAULT_PIN));
    await progressfn(progress++, max_progress);

    status_res = await Webcrypt_Status(logfn);
    TEST(status_res.UNLOCKED, "session should be open", logfn);
    await progressfn(progress++, max_progress);

    await Webcrypt_Logout(logfn);
    status_res = await Webcrypt_Status(logfn);
    TEST(!status_res.UNLOCKED, "session should be closed", logfn);
    await progressfn(progress++, max_progress);

    await Webcrypt_Login(logfn, new CommandLoginParams(DEFAULT_PIN));
    await progressfn(progress++, max_progress);

    const hash = get_hash("TEST HASH");

    {
        const kh = await Webcrypt_GenerateKey(logfn);
        await logfn(JSON.stringify(kh));
        await progressfn(progress++, max_progress);
        const sign = await Webcrypt_Sign(logfn, new CommandSignParams(hash, kh.KEYHANDLE));
        await logfn(JSON.stringify(sign));
        await progressfn(progress++, max_progress);
    }

    {
        const kh_data = await Webcrypt_GenerateKeyFromData(logfn, new CommandGenerateKeyFromDataParams(hash));
        await logfn(JSON.stringify(kh_data));
        await progressfn(progress++, max_progress);
        const sign_data = await Webcrypt_Sign(logfn, new CommandSignParams(hash, kh_data.KEYHANDLE));
        await logfn(JSON.stringify(sign_data));
        await progressfn(progress++, max_progress);
    }

    {
        const kh_rk_data = await Webcrypt_GenerateResidentKey(logfn);
        await logfn(JSON.stringify(kh_rk_data));
        await progressfn(progress++, max_progress);
        const sign_data = await Webcrypt_Sign(logfn, new CommandSignParams(hash, kh_rk_data.KEYHANDLE));
        await logfn(JSON.stringify(sign_data));
        await progressfn(progress++, max_progress);
        const rk_public = await Webcrypt_ReadResidentKeyPublic(logfn, new CommandReadResidentKeyPublicParams(kh_rk_data.KEYHANDLE));
        await logfn(JSON.stringify(rk_public.PUBKEY));
        TEST(rk_public.PUBKEY == kh_rk_data.PUBKEY, "public key of resident key should be the same", logfn);
        await progressfn(progress++, max_progress);
    }

    {
        const init = await Webcrypt_InitializeSeed(logfn, new CommandInitializeSeedParams(""));
        await logfn(JSON.stringify(init));
        await progressfn(progress++, max_progress);

        const restore = await Webcrypt_RestoreFromSeed(logfn, new CommandRestoreFromSeedParams("00", "00"));
        await logfn(JSON.stringify(restore));
        await progressfn(progress++, max_progress);
    }

    {
        await should_throw(logfn, async () => {
            await Webcrypt_WriteResidentKey(logfn, new CommandWriteResidentKeyParams("00"));
        }, "ERR_FAILED_LOADING_DATA");
        await progressfn(progress++, max_progress);
    }

    {
        const res = await Webcrypt_GetConfiguration(logfn);
        await logfn(JSON.stringify(res));
        await progressfn(progress++, max_progress);

        // const new_confirmation_value = "02";
        // await Webcrypt_SetConfiguration(logfn, new CommandSetConfigurationParams(new_confirmation_value));
        // const res2 = await Webcrypt_GetConfiguration(logfn);
        // TEST(res2.CONFIRMATION == new_confirmation_value, "new confirmation value should be saved", logfn);
        // await progressfn(progress++, max_progress);
    }

    {
        await should_throw(logfn, async () => {
            await Webcrypt_Decrypt(logfn, new CommandDecryptParams("", "", "", ""));
        }, "ERR_BAD_FORMAT");
        await progressfn(progress++, max_progress);
    }

    try
    {
        const kh = await Webcrypt_GenerateKey(logfn);
        const encryptText = "text to encrypt, but even longer and longer";
        const PUBKEY = kh.PUBKEY;
        const KEYHANDLE = kh.KEYHANDLE;

        const commandDecryptParams = await WEBCRYPT_ENCRYPT(logfn, encryptText, PUBKEY, KEYHANDLE);
        await logfn(JSON.stringify(commandDecryptParams));
        await progressfn(progress++, max_progress);

        const decrypt_result = await Webcrypt_Decrypt(logfn, commandDecryptParams);
        await logfn(JSON.stringify(decrypt_result));
        const decoder = new TextDecoder();
        const decoded_text = decoder.decode(hexStringToByte(decrypt_result.DATA));

        const text_len = uint8ToUint16(hexStringToByte(decrypt_result.DATA).slice(0,2), true);
        const decoded_text_no_pad_cut = decoder.decode( hexStringToByte(decrypt_result.DATA).slice(2, text_len+2) );

        await logfn(JSON.stringify(decoded_text));
        await logfn(JSON.stringify(decoded_text_no_pad_cut));
        await progressfn(progress++, max_progress);

        TEST(decoded_text_no_pad_cut == encryptText, `${decoded_text_no_pad_cut} == ${encryptText}`, logfn);
    }
    catch (e) {
        await logfn(JSON.stringify(e));
        throw e;
    }

}

