// Copyright 2022 Nitrokey GmbH
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

import {log_message_library} from "./logs";

export class Session {
    private validPeriod: number = 60000; //const
    private TP: string = '';
    private validUntil: number = 0;

    constructor() {
        this.TP = '';
    }
    public clear() {
        this.TP = '';
    }

    public get token(): string {
        return this.TP;
    }

    private getSecondsEpoch() {
        return new Date().getTime()/1000;
    }

    public set token(token: string) {
        log_message_library(`Auth token set: '${token.slice(0,4).toString()}'`);
        this.TP = token;
        this.validUntil = this.getSecondsEpoch() + this.validPeriod;
    }

    public timeLeft():number{
        if (!this.valid())
            return 0;
        return this.validUntil - this.getSecondsEpoch();
    }

    public valid():boolean {
        return this.getSecondsEpoch() < this.validUntil && this.TP !== undefined && this.TP.length !== 0;
    }

    public authorize(data: any) {
        log_message_library(`Auth token '${this.TP.slice(0,4).toString()}' valid for the next ${this.timeLeft().toFixed(1)} seconds`);
        if (!this.valid()) {
            if (this.validUntil !== 0) console.warn('Temporary authorization token is not valid anymore. Clearing state.');
            this.clear();
        }
        if (!data){
            data = {};
        }

        // data['TP'] = this.TP;
        data['TP'] = new Uint8Array(4);
        return data;
    }

}
