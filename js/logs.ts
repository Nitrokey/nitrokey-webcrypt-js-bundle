// Copyright 2022 Nitrokey GmbH
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

export const library_initialization_time_ms = Date.now();

export function log_message_library(s: string, ...args: any[]) {
    s = prefix_with_timestamp(s, '*WC');
    args = [s].concat(args);
    // @ts-ignore
    console.log.apply(console, args);
}

export function log_message(s: string) {
    s = prefix_with_timestamp(s);
    console.log(s);
    let logs = document.getElementById("console");
    if (logs) {
        logs.innerHTML = logs.innerHTML + s + '\r\n';
        logs.scrollTop = logs.scrollHeight;
    }
}

function prefix_with_timestamp(s: string, prefix = '*') {
    const time = ((Date.now() - library_initialization_time_ms) / 1000).toFixed(1);
    s = `${prefix} [${time}] ` + s;
    return s;
}

export async function log_fn(statusText: string): Promise<void> {
    log_function_library(statusText);
}

// let log_function_library = (message: string) => console.log(message);
let log_function_library = (message: string) => log_message(message);

export function set_log_webcrypt(func: any){
    log_function_library = func;
}
