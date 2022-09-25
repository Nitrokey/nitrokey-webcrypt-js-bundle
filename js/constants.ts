// Copyright 2022 Nitrokey GmbH
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


export const VERBOSE = false;


export enum CMD {
    WEBCRYPT = 0x22,
}

export enum WEBCRYPT_CMD {
    STATUS = 0x00,
    /// Test command - just return the received data
    TEST_PING = 0x01,
    /// Test command - clear user data without confirmation
    TEST_CLEAR = 0x02,
    /// Test command - issue reboot command to the host, if configured
    TEST_REBOOT = 0x03,
    /// Unlock access through FIDO U2F. Available for FIDO U2F compatibility.  FIDO2 should use native PIN handling.
    LOGIN = 0x04,
    /// Lock access through FIDO U2F. Available for FIDO U2F compatibility.
    LOGOUT = 0x05,
    /// Action should be equal in effect to calling FIDO2 reset
    FACTORY_RESET = 0x06,
    /// Return PIN attempts' counter value. @DEPRECATED by STATUS command.
    PIN_ATTEMPTS = 0x07,
    /// Set user options, like when to ask for the touch confirmation or PIN
    SET_CONFIGURATION = 0x08,
    GET_CONFIGURATION = 0x09,
    SET_PIN = 0x0A,
    CHANGE_PIN = 0x0B,

    /// Initialize Webcrypt's secrets
    INITIALIZE_SEED = 0x10,
    /// Restore Webcrypt secrets from the provided data
    RESTORE_FROM_SEED = 0x11,
    /// Generate a key and return it to the callee as key handle
    GENERATE_KEY = 0x12,
    /// Sign data with key handle
    SIGN = 0x13,
    /// Decrypt data with key handle
    DECRYPT = 0x14,
    /// Generate a key from the provided data
    GENERATE_KEY_FROM_DATA = 0x15,

    /// Write a Resident Key from the provided data
    GENERATE_RESIDENT_KEY = 0x16,
    /// Read public key of the Resident Key
    READ_RESIDENT_KEY_PUBLIC = 0x17,
    /// Discover Resident Keys related to this RP
    DISCOVER_RESIDENT_KEYS = 0x18,
    /// Write RAW key as received from the RP
    WRITE_RESIDENT_KEY = 0x19,

    OPENPGP_DECRYPT = 0x20,
    OPENPGP_SIGN = 0x21,
    OPENPGP_INFO = 0x22,
    OPENPGP_IMPORT= 0x23,
    OPENPGP_GENERATE = 0x24,

    /// Implementation detail: default value
    NOT_SET = 0xFE,
}

export enum WEBCRYPT_DEVICE_COMM  {
    SEND = 0x01,
    RECEIVE = 0x02,
}

export const WEBCRYPT_CONSTANTS = {
    CHUNK_SIZE_RECEIVE: 69,
    CHUNK_SIZE_SEND: 41, // chrome: works with 41
    COMM_OFFSET: 0,
    BUFFER_SIZE: 1024,
    TIMEOUT: 1000,
};

interface NumberToStringMap {
    [id: number]: string;
}


export const command_codes: NumberToStringMap = {
	0x22: "WEBCRYPT",
};

export const ctap_error_codes: NumberToStringMap = {
    0x00: 'CTAP1_SUCCESS',
    0x01: 'CTAP1_ERR_INVALID_COMMAND',
    0x02: 'CTAP1_ERR_INVALID_PARAMETER',
    0x03: 'CTAP1_ERR_INVALID_LENGTH',
    0x04: 'CTAP1_ERR_INVALID_SEQ',
    0x05: 'CTAP1_ERR_TIMEOUT',
    0x06: 'CTAP1_ERR_CHANNEL_BUSY',
    0x0A: 'CTAP1_ERR_LOCK_REQUIRED',
    0x0B: 'CTAP1_ERR_INVALID_CHANNEL',

    0x10: 'CTAP2_ERR_CBOR_PARSING',
    0x11: 'CTAP2_ERR_CBOR_UNEXPECTED_TYPE',
    0x12: 'CTAP2_ERR_INVALID_CBOR',
    0x13: 'CTAP2_ERR_INVALID_CBOR_TYPE',
    0x14: 'CTAP2_ERR_MISSING_PARAMETER',
    0x15: 'CTAP2_ERR_LIMIT_EXCEEDED',
    0x16: 'CTAP2_ERR_UNSUPPORTED_EXTENSION',
    0x17: 'CTAP2_ERR_TOO_MANY_ELEMENTS',
    0x18: 'CTAP2_ERR_EXTENSION_NOT_SUPPORTED',
    0x19: 'CTAP2_ERR_CREDENTIAL_EXCLUDED',
    0x20: 'CTAP2_ERR_CREDENTIAL_NOT_VALID',
    0x21: 'CTAP2_ERR_PROCESSING',
    0x22: 'CTAP2_ERR_INVALID_CREDENTIAL',
    0x23: 'CTAP2_ERR_USER_ACTION_PENDING',
    0x24: 'CTAP2_ERR_OPERATION_PENDING',
    0x25: 'CTAP2_ERR_NO_OPERATIONS',
    0x26: 'CTAP2_ERR_UNSUPPORTED_ALGORITHM',
    0x27: 'CTAP2_ERR_OPERATION_DENIED',
    0x28: 'CTAP2_ERR_KEY_STORE_FULL',
    0x29: 'CTAP2_ERR_NOT_BUSY',
    0x2A: 'CTAP2_ERR_NO_OPERATION_PENDING',
    0x2B: 'CTAP2_ERR_UNSUPPORTED_OPTION',
    0x2C: 'CTAP2_ERR_INVALID_OPTION',
    0x2D: 'CTAP2_ERR_KEEPALIVE_CANCEL',
    0x2E: 'CTAP2_ERR_NO_CREDENTIALS',
    0x2F: 'CTAP2_ERR_USER_ACTION_TIMEOUT',
    0x30: 'CTAP2_ERR_NOT_ALLOWED',
    0x31: 'CTAP2_ERR_PIN_INVALID',
    0x32: 'CTAP2_ERR_PIN_BLOCKED',
    0x33: 'CTAP2_ERR_PIN_AUTH_INVALID',
    0x34: 'CTAP2_ERR_PIN_AUTH_BLOCKED',
    0x35: 'CTAP2_ERR_PIN_NOT_SET',
    0x36: 'CTAP2_ERR_PIN_REQUIRED',
    0x37: 'CTAP2_ERR_PIN_POLICY_VIOLATION',
    0x38: 'CTAP2_ERR_PIN_TOKEN_EXPIRED',
    0x39: 'CTAP2_ERR_REQUEST_TOO_LARGE',
};


export const errcode_to_string: NumberToStringMap = {
    0x00: "ERR_SUCCESS",
    0xF0: "ERR_REQ_AUTH",
    0xF1: "ERR_INVALID_PIN",
    0xF2: "ERR_NOT_ALLOWED",
    0xF3: "ERR_BAD_FORMAT",
    0xF4: "ERR_USER_NOT_PRESENT",
    0xF5: "ERR_FAILED_LOADING_DATA",
    0xF6: "ERR_INVALID_CHECKSUM",
    0xF7: "ERR_ALREADY_IN_DATABASE",
    0xF8: "ERR_NOT_FOUND",
    0xF9: "ERR_ASSERT_FAILED",
    0xFA: "ERR_INTERNAL_ERROR",
    0xFB: "ERR_MEMORY_FULL",
    0xFC: "ERR_NOT_IMPLEMENTED",
    0xFD: "ERR_BAD_ORIGIN",
    0xFE: "ERR_NOT_SET",
    0xFF: "ERR_INVALID_COMMAND",
}

export const string_to_errcode = Object.assign(
	{},
	...Object.entries(errcode_to_string).map(
		([a, b]) => ({[b]: a})
	)
);


export const command_to_string: NumberToStringMap = {
    0x00: "STATUS",
    0x01: "TEST_PING",
    0x02: "TEST_CLEAR",
    0x03: "TEST_REBOOT",
    0x04: "LOGIN",
    0x05: "LOGOUT",
    0x06: "FACTORY_RESET",
    0x07: "PIN_ATTEMPTS",
    0x08: "SET_CONFIGURATION",
    0x09: "GET_CONFIGURATION",
    0x0A: "SET_PIN",
    0x0B: "CHANGE_PIN",

    0x10: "INITIALIZE_SEED",
    0x11: "RESTORE_FROM_SEED",
    0x12: "GENERATE_KEY",
    0x13: "SIGN",
    0x14: "DECRYPT",
    0x15: "GENERATE_KEY_FROM_DATA",
    0x16: "GENERATE_RESIDENT_KEY",
    0x17: "READ_RESIDENT_KEY_PUBLIC",
    0x18: "DISCOVER_RESIDENT_KEYS",
    0x19: "WRITE_RESIDENT_KEY",

    0x20: "OPENPGP_DECRYPT",
    0x21: "OPENPGP_SIGN",
    0x22: "OPENPGP_INFO",
    0x23: "OPENPGP_IMPORT",
    0x24: "OPENPGP_INIT",

    0xFE: "NOT_SET",
};

export const string_to_command = Object.assign(
    {},
    ...Object.entries(command_to_string).map(
        ([a, b]) => ({[b]: a})
    )
);


export const ERROR_CBOR_PARSING = 0x10;


export const commands_parameters: Record<string, Record<string, string>> = {
    "STATUS": {},
    "TEST_PING": {},
    "TEST_CLEAR": {},
    "TEST_REBOOT": {},
    "LOGIN": {"PIN": "string"},
    "LOGOUT": {},
    "FACTORY_RESET": {},
    // "PIN_ATTEMPTS": {  },
    "SET_CONFIGURATION": {"CONFIRMATION": "number"},
    "GET_CONFIGURATION": {},
    "SET_PIN": {"PIN": "string"},
    "CHANGE_PIN": {"PIN": "string", "NEWPIN": "string"},

    "INITIALIZE_SEED": {"ENTROPY": "bytes"},
    "RESTORE_FROM_SEED": {"MASTER": "bytes", "SALT": "bytes"},
    "GENERATE_KEY": {},
    "SIGN": {"HASH": "bytes", "KEYHANDLE": "bytes"},
    "DECRYPT": {"DATA": "bytes", "KEYHANDLE": "bytes", "HMAC": "bytes", "ECCEKEY": "bytes"},
    "GENERATE_KEY_FROM_DATA": {"HASH": "bytes"},

    "GENERATE_RESIDENT_KEY": {},
    "READ_RESIDENT_KEY_PUBLIC": {"KEYHANDLE": "bytes"},
    "DISCOVER_RESIDENT_KEYS": {},
    "WRITE_RESIDENT_KEY": {"RAW_KEY_DATA": "bytes"},
};
