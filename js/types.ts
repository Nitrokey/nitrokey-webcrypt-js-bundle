// Copyright 2022 Nitrokey GmbH
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

export class WCKeyDetails {
    public pubkey: string;
    public keyhandle: string;

    constructor(pk: string, kh: string) {
        this.keyhandle = kh;
        this.pubkey = pk;
    }

}

export interface Dictionary {
    [key: string]: number|Uint8Array|string|object
}

export type StatusCallback = (statusText: string) => Promise<void>;
export type ProgressCallback = (x: number, max:number) => Promise<void>;
