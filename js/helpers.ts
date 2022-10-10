// Copyright 2022 Nitrokey GmbH
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

import {Dictionary, StatusCallback} from "./types";

class TestError extends Error {

}

export function TEST(tested_condition: boolean, test_description: string, logfn: StatusCallback = async ()=>{} ): void{
    if (tested_condition) {
        if (test_description ){
            const message = "+++ PASS: " + test_description;
            console.log(message);
            logfn(message);
        }
    }
    else {
        const message_fail = "--- TEST FAIL: " + test_description;
        console.log(message_fail);
        logfn(message_fail);
        throw new TestError(message_fail);
    }
}

export function byteToHexString(uint8arr: Uint8Array): string {
    if (!uint8arr) {
        return '';
    }
    let hexStr = '';
    for (let i = 0; i < uint8arr.length; i++) {
        let hex = (uint8arr[i] & 0xff).toString(16);
        hex = (hex.length === 1) ? '0' + hex : hex;
        hexStr += hex;
    }
    return hexStr.toUpperCase();
}

export function hexStringToByte(str: string): Uint8Array {
    if (!str) {
        return new Uint8Array();
    }
    const a = [];
    for (let i = 0, len = str.length; i < len; i+=2) {
        a.push(parseInt(str.substr(i,2),16));
    }
    return new Uint8Array(a);
}


export function uint8ToUint16(uint_arr: Uint8Array, littleEndian = false) {
    return (new DataView(uint_arr.buffer)).getUint16(0, littleEndian);
}

export function flatten(u8_arr_arr: Array<Uint8Array>): Uint8Array{
    let s= 0;
    for (let i = 0; i < u8_arr_arr.length; i++) {
        s+= u8_arr_arr[i].length;
    }

    let res = new Uint8Array(s);
    let offset = 0;
    for (let i = 0; i < u8_arr_arr.length; i++) {
        res.set(u8_arr_arr[i], offset);
        offset += u8_arr_arr[i].length;
    }
    return res;
}

export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
    let c = new Uint8Array(a.length + b.length);
    c.set(a, 0); // FIXME handle empty/null arguments
    c.set(b, a.length);
    return c;
}

export function int2arr(uint: number): Uint8Array {
    let uint_arr = new Uint8Array(1);
    uint_arr[0] = uint;
    return uint_arr;
}

export function values(dictionary: Dictionary) {
    let i, arr = [];
    for(i in dictionary) {
        arr.push(dictionary[i]);
    }
    return arr;
}

export function keys(dictionary:Dictionary): string[] {
    let i, arr = [];
    for(i in dictionary) {
        arr.push(i);
    }
    return arr;
}

export function items(dict: Dictionary){
    let ret = [];
    for(let v in dict){
        ret.push(Object.freeze([v, dict[v]]));
    }
    return Object.freeze(ret);
}

export function getBinaryStr(data: string): Uint8Array {

    return new TextEncoder().encode(data);
}

export function dict_binval(dictionary:Dictionary):Dictionary {
    let res: Dictionary = {};
    for(let i in dictionary) {
        if (typeof dictionary[i] === "object"){
            res[i] = dictionary[i];
        } else if (i === "PIN" || i === "NEWPIN") {
            res[i] = getBinaryStr(<string>dictionary[i]);
        } else {
            res[i] = hexStringToByte(<string>dictionary[i]);
        }
    }
    // console.log("dict_binval",dictionary, res);
    return res;
}

export function clone_object(obj:any) {
    return JSON.parse(JSON.stringify(obj));
}

export function dict_hexval(dictionary:Dictionary):Dictionary {
    let res: Dictionary = {};
    for(let i in dictionary) {
        if (typeof dictionary[i] === "object"){ // Uint8Array
            res[i] = byteToHexString(<Uint8Array>dictionary[i]);
        } else {
            res[i] = dictionary[i];
        }
    }
    return res;
}

export function dict_empty(dict: Dictionary): boolean {
    return Object.keys(dict).length === 0
}

export function delay(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export async function get_hash(o: string) {
    // import {sha256} from "js-sha256";
    // return sha256(o);
    const buffer = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(o));
    return byteToHexString(new Uint8Array(buffer));
}

export async function generate_key_ecc(): Promise<CryptoKeyPair> {
    const algorithm = {
        name: "ECDH",
        namedCurve: "P-256",
    };
    return await window.crypto.subtle.generateKey(
        algorithm,
        true,
        ["deriveKey"]
    ) as CryptoKeyPair ;
}

export async function agree_on_key(privateKey: CryptoKey, publicKey: CryptoKey) {
    return window.crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: publicKey
        },
        privateKey,
        {
            name: "AES-CBC",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
}

export async function encode_text(text:string) : Promise<Uint8Array> {
    return new TextEncoder().encode(text);
}

export async function encrypt_aes(key:CryptoKey, data:Uint8Array): Promise<ArrayBuffer> {
    const encoded = data;
    const iv = new Uint8Array(16).fill(0);
    return window.crypto.subtle.encrypt(
        {
            name: "AES-CBC",
            iv: iv,
            length: 256,
        },
        key,
        encoded,
    );
}

export async function calculate_hmac(key_in:CryptoKey, data:Uint8Array) {
    const algorithm = { name: 'HMAC', hash: 'SHA-256' };
    const encoder = new TextEncoder();

    const keyraw = await export_key(key_in);

    const key = await crypto.subtle.importKey(
        'raw',
        keyraw,
        algorithm,
        true,
        ['sign', 'verify']
    );

    return await window.crypto.subtle.sign(
        "HMAC",
        key,
        data
    );
}

export async function number_to_short(n:number): Promise<ArrayBuffer> {
    const buffer = new ArrayBuffer(2);
    const dataView = new DataView(buffer);
    dataView.setInt16(0, n, true);
    return dataView.buffer;
}

export async function ecdsa_to_ecdh(pk:CryptoKey):Promise<CryptoKey> {
    return await crypto.subtle.importKey('raw', await crypto.subtle.exportKey('raw', pk), {
            name: "ecdh",
            namedCurve: "P-256"
        },
        true,
        []
    );
}

export async function import_key(data:Uint8Array):Promise<CryptoKey> {
    const algorithm = {
        name: "ECDSA",
        // hash: {name: "SHA-256"},
        namedCurve: "P-256",
    };
    return await crypto.subtle.importKey(
        'raw',
        data,
        algorithm,
        true,
        // ["deriveKey"]
        ["verify"]
    );
}

export async function export_key(key: CryptoKey): Promise<Uint8Array> {
    const exported = await window.crypto.subtle.exportKey(
        "raw",
        key
    );
    return new Uint8Array(exported);
}

export function buffer_to_uint8(buf: ArrayBuffer) {
    return new Uint8Array(buf as ArrayBuffer);
}

export function round_to_next(x:number, n:number): number
{
    return x + n - x % n;
}

export function pkcs7_pad_16(arr:Uint8Array): Uint8Array {
    const s = arr.length;
    const s_pad = round_to_next(s, 16);

    const arr_padded = new Uint8Array(s_pad).fill(s_pad-s);
    arr_padded.set(arr);
    return arr_padded;
}
export function remove_pkcs7_pad_16(arr:Uint8Array): Uint8Array {
    const pad_value = arr[arr.length-1];
    if (pad_value>16){
        return arr;
    }
    return arr.slice(0, arr.length-1-pad_value);
}

export function equalBuffer (buf1:Uint8Array, buf2:Uint8Array)
{
    if (buf1.byteLength != buf2.byteLength) return false;
    for (let i = 0 ; i != buf1.byteLength ; i++)
    {
        if (buf1[i] != buf2[i]) return false;
    }
    return true;
}
