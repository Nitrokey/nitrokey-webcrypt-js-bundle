// Copyright 2022 Nitrokey GmbH
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


import {JS_API_VERSION} from "./version";
import {log_message_library} from "./logs";

// let platform = require('./vendor/platform.js');
// import * as platfrom from './vendor/platform'

export function webauthn_supported(): boolean {
    return window.PublicKeyCredential !== undefined;
}

export async function gather_platform_info() {
    // const platform_description = platform.description;
    const platform_description = 'NONE';
    log_message_library(`Nitrokey Webcrypt API Version: ${JS_API_VERSION}`);
    log_message_library(`Platform: ${platform_description}; Webauthn support: ${webauthn_supported()}`);

}
