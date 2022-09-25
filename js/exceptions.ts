// Copyright 2022 Nitrokey GmbH

import { errcode_to_string} from "./constants";

export class CommandExecutionError extends Error {
    public errcode : number = 0;
    public name : string = '';
    constructor(m: string, errcode:number) {
        super('CommandExecutionError - ' + m + ' - ' +errcode_to_string[errcode] +  ' ' + errcode.toString() + ' ' + 'hex: 0x'+errcode.toString(16));

        // Set the prototype explicitly.
        Object.setPrototypeOf(this, CommandExecutionError.prototype);
        this.errcode = errcode;
        this.name = errcode_to_string[errcode];
    }
}
