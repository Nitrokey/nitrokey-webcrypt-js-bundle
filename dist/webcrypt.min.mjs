var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// js/vendor/cbor.js
var require_cbor = __commonJS({
  "js/vendor/cbor.js"(exports, module) {
    "use strict";
    (function(global, undefined2) {
      "use strict";
      var POW_2_24 = 5960464477539063e-23, POW_2_32 = 4294967296, POW_2_53 = 9007199254740992;
      function encode2(value) {
        var data = new ArrayBuffer(256);
        var dataView = new DataView(data);
        var lastLength;
        var offset = 0;
        function prepareWrite(length) {
          var newByteLength = data.byteLength;
          var requiredLength = offset + length;
          while (newByteLength < requiredLength)
            newByteLength <<= 1;
          if (newByteLength !== data.byteLength) {
            var oldDataView = dataView;
            data = new ArrayBuffer(newByteLength);
            dataView = new DataView(data);
            var uint32count = offset + 3 >> 2;
            for (var i2 = 0; i2 < uint32count; ++i2)
              dataView.setUint32(i2 << 2, oldDataView.getUint32(i2 << 2));
          }
          lastLength = length;
          return dataView;
        }
        function commitWrite() {
          offset += lastLength;
        }
        function writeFloat64(value2) {
          commitWrite(prepareWrite(8).setFloat64(offset, value2));
        }
        function writeUint8(value2) {
          commitWrite(prepareWrite(1).setUint8(offset, value2));
        }
        function writeUint8Array(value2) {
          var dataView2 = prepareWrite(value2.length);
          for (var i2 = 0; i2 < value2.length; ++i2)
            dataView2.setUint8(offset + i2, value2[i2]);
          commitWrite();
        }
        function writeUint16(value2) {
          commitWrite(prepareWrite(2).setUint16(offset, value2));
        }
        function writeUint32(value2) {
          commitWrite(prepareWrite(4).setUint32(offset, value2));
        }
        function writeUint64(value2) {
          var low = value2 % POW_2_32;
          var high = (value2 - low) / POW_2_32;
          var dataView2 = prepareWrite(8);
          dataView2.setUint32(offset, high);
          dataView2.setUint32(offset + 4, low);
          commitWrite();
        }
        function writeTypeAndLength(type, length) {
          if (length < 24) {
            writeUint8(type << 5 | length);
          } else if (length < 256) {
            writeUint8(type << 5 | 24);
            writeUint8(length);
          } else if (length < 65536) {
            writeUint8(type << 5 | 25);
            writeUint16(length);
          } else if (length < 4294967296) {
            writeUint8(type << 5 | 26);
            writeUint32(length);
          } else {
            writeUint8(type << 5 | 27);
            writeUint64(length);
          }
        }
        function encodeItem(value2) {
          var i2;
          if (value2 === false)
            return writeUint8(244);
          if (value2 === true)
            return writeUint8(245);
          if (value2 === null)
            return writeUint8(246);
          if (value2 === undefined2)
            return writeUint8(247);
          switch (typeof value2) {
            case "number":
              if (Math.floor(value2) === value2) {
                if (0 <= value2 && value2 <= POW_2_53)
                  return writeTypeAndLength(0, value2);
                if (-POW_2_53 <= value2 && value2 < 0)
                  return writeTypeAndLength(1, -(value2 + 1));
              }
              writeUint8(251);
              return writeFloat64(value2);
            case "string":
              var utf8data = [];
              for (i2 = 0; i2 < value2.length; ++i2) {
                var charCode = value2.charCodeAt(i2);
                if (charCode < 128) {
                  utf8data.push(charCode);
                } else if (charCode < 2048) {
                  utf8data.push(192 | charCode >> 6);
                  utf8data.push(128 | charCode & 63);
                } else if (charCode < 55296) {
                  utf8data.push(224 | charCode >> 12);
                  utf8data.push(128 | charCode >> 6 & 63);
                  utf8data.push(128 | charCode & 63);
                } else {
                  charCode = (charCode & 1023) << 10;
                  charCode |= value2.charCodeAt(++i2) & 1023;
                  charCode += 65536;
                  utf8data.push(240 | charCode >> 18);
                  utf8data.push(128 | charCode >> 12 & 63);
                  utf8data.push(128 | charCode >> 6 & 63);
                  utf8data.push(128 | charCode & 63);
                }
              }
              writeTypeAndLength(3, utf8data.length);
              return writeUint8Array(utf8data);
            default:
              var length;
              if (Array.isArray(value2)) {
                length = value2.length;
                writeTypeAndLength(4, length);
                for (i2 = 0; i2 < length; ++i2)
                  encodeItem(value2[i2]);
              } else if (value2 instanceof Uint8Array) {
                writeTypeAndLength(2, value2.length);
                writeUint8Array(value2);
              } else {
                var keys = Object.keys(value2);
                length = keys.length;
                writeTypeAndLength(5, length);
                for (i2 = 0; i2 < length; ++i2) {
                  var key = keys[i2];
                  encodeItem(key);
                  encodeItem(value2[key]);
                }
              }
          }
        }
        encodeItem(value);
        if ("slice" in data)
          return data.slice(0, offset);
        var ret = new ArrayBuffer(offset);
        var retView = new DataView(ret);
        for (var i = 0; i < offset; ++i)
          retView.setUint8(i, dataView.getUint8(i));
        return ret;
      }
      function decode2(data, tagger, simpleValue) {
        var dataView = new DataView(data);
        var offset = 0;
        if (typeof tagger !== "function")
          tagger = function(value) {
            return value;
          };
        if (typeof simpleValue !== "function")
          simpleValue = function() {
            return undefined2;
          };
        function commitRead(length, value) {
          offset += length;
          return value;
        }
        function readArrayBuffer(length) {
          return commitRead(length, new Uint8Array(data, offset, length));
        }
        function readFloat16() {
          var tempArrayBuffer = new ArrayBuffer(4);
          var tempDataView = new DataView(tempArrayBuffer);
          var value = readUint16();
          var sign = value & 32768;
          var exponent = value & 31744;
          var fraction = value & 1023;
          if (exponent === 31744)
            exponent = 255 << 10;
          else if (exponent !== 0)
            exponent += 127 - 15 << 10;
          else if (fraction !== 0)
            return (sign ? -1 : 1) * fraction * POW_2_24;
          tempDataView.setUint32(0, sign << 16 | exponent << 13 | fraction << 13);
          return tempDataView.getFloat32(0);
        }
        function readFloat32() {
          return commitRead(4, dataView.getFloat32(offset));
        }
        function readFloat64() {
          return commitRead(8, dataView.getFloat64(offset));
        }
        function readUint8() {
          return commitRead(1, dataView.getUint8(offset));
        }
        function readUint16() {
          return commitRead(2, dataView.getUint16(offset));
        }
        function readUint32() {
          return commitRead(4, dataView.getUint32(offset));
        }
        function readUint64() {
          return readUint32() * POW_2_32 + readUint32();
        }
        function readBreak() {
          if (dataView.getUint8(offset) !== 255)
            return false;
          offset += 1;
          return true;
        }
        function readLength(additionalInformation) {
          if (additionalInformation < 24)
            return additionalInformation;
          if (additionalInformation === 24)
            return readUint8();
          if (additionalInformation === 25)
            return readUint16();
          if (additionalInformation === 26)
            return readUint32();
          if (additionalInformation === 27)
            return readUint64();
          if (additionalInformation === 31)
            return -1;
          throw "Invalid length encoding";
        }
        function readIndefiniteStringLength(majorType) {
          var initialByte = readUint8();
          if (initialByte === 255)
            return -1;
          var length = readLength(initialByte & 31);
          if (length < 0 || initialByte >> 5 !== majorType)
            throw "Invalid indefinite length element";
          return length;
        }
        function appendUtf16Data(utf16data, length) {
          for (var i = 0; i < length; ++i) {
            var value = readUint8();
            if (value & 128) {
              if (value < 224) {
                value = (value & 31) << 6 | readUint8() & 63;
                length -= 1;
              } else if (value < 240) {
                value = (value & 15) << 12 | (readUint8() & 63) << 6 | readUint8() & 63;
                length -= 2;
              } else {
                value = (value & 15) << 18 | (readUint8() & 63) << 12 | (readUint8() & 63) << 6 | readUint8() & 63;
                length -= 3;
              }
            }
            if (value < 65536) {
              utf16data.push(value);
            } else {
              value -= 65536;
              utf16data.push(55296 | value >> 10);
              utf16data.push(56320 | value & 1023);
            }
          }
        }
        function decodeItem() {
          var initialByte = readUint8();
          var majorType = initialByte >> 5;
          var additionalInformation = initialByte & 31;
          var i;
          var length;
          if (majorType === 7) {
            switch (additionalInformation) {
              case 25:
                return readFloat16();
              case 26:
                return readFloat32();
              case 27:
                return readFloat64();
            }
          }
          length = readLength(additionalInformation);
          if (length < 0 && (majorType < 2 || 6 < majorType))
            throw "Invalid length";
          switch (majorType) {
            case 0:
              return length;
            case 1:
              return -1 - length;
            case 2:
              if (length < 0) {
                var elements = [];
                var fullArrayLength = 0;
                while ((length = readIndefiniteStringLength(majorType)) >= 0) {
                  fullArrayLength += length;
                  elements.push(readArrayBuffer(length));
                }
                var fullArray = new Uint8Array(fullArrayLength);
                var fullArrayOffset = 0;
                for (i = 0; i < elements.length; ++i) {
                  fullArray.set(elements[i], fullArrayOffset);
                  fullArrayOffset += elements[i].length;
                }
                return fullArray;
              }
              return readArrayBuffer(length);
            case 3:
              var utf16data = [];
              if (length < 0) {
                while ((length = readIndefiniteStringLength(majorType)) >= 0)
                  appendUtf16Data(utf16data, length);
              } else
                appendUtf16Data(utf16data, length);
              return String.fromCharCode.apply(null, utf16data);
            case 4:
              var retArray;
              if (length < 0) {
                retArray = [];
                while (!readBreak())
                  retArray.push(decodeItem());
              } else {
                retArray = new Array(length);
                for (i = 0; i < length; ++i)
                  retArray[i] = decodeItem();
              }
              return retArray;
            case 5:
              var retObject = {};
              for (i = 0; i < length || length < 0 && !readBreak(); ++i) {
                var key = decodeItem();
                retObject[key] = decodeItem();
              }
              return retObject;
            case 6:
              return tagger(decodeItem(), length);
            case 7:
              switch (length) {
                case 20:
                  return false;
                case 21:
                  return true;
                case 22:
                  return null;
                case 23:
                  return undefined2;
                default:
                  return simpleValue(length);
              }
          }
        }
        var ret = decodeItem();
        if (offset !== data.byteLength)
          throw "Remaining bytes";
        return ret;
      }
      var obj = { encode: encode2, decode: decode2 };
      if (typeof define === "function" && define.amd)
        define("cbor/cbor", obj);
      else if (typeof module !== "undefined" && module.exports)
        module.exports = obj;
      else if (!global.CBOR)
        global.CBOR = obj;
    })(exports);
  }
});

// js/transport.ts
var CBOR = __toESM(require_cbor());

// js/constants.ts
var VERBOSE = false;
var WEBCRYPT_CONSTANTS = {
  CHUNK_SIZE_RECEIVE: 69,
  CHUNK_SIZE_SEND: 41,
  COMM_OFFSET: 0,
  BUFFER_SIZE: 1024,
  TIMEOUT: 1e3
};
var command_codes = {
  34: "WEBCRYPT"
};
var errcode_to_string = {
  0: "ERR_SUCCESS",
  240: "ERR_REQ_AUTH",
  241: "ERR_INVALID_PIN",
  242: "ERR_NOT_ALLOWED",
  243: "ERR_BAD_FORMAT",
  244: "ERR_USER_NOT_PRESENT",
  245: "ERR_FAILED_LOADING_DATA",
  246: "ERR_INVALID_CHECKSUM",
  247: "ERR_ALREADY_IN_DATABASE",
  248: "ERR_NOT_FOUND",
  249: "ERR_ASSERT_FAILED",
  250: "ERR_INTERNAL_ERROR",
  251: "ERR_MEMORY_FULL",
  252: "ERR_NOT_IMPLEMENTED",
  253: "ERR_BAD_ORIGIN",
  254: "ERR_NOT_SET",
  255: "ERR_INVALID_COMMAND"
};
var string_to_errcode = Object.assign(
  {},
  ...Object.entries(errcode_to_string).map(
    ([a, b]) => ({ [b]: a })
  )
);
var command_to_string = {
  0: "STATUS",
  1: "TEST_PING",
  2: "TEST_CLEAR",
  3: "TEST_REBOOT",
  4: "LOGIN",
  5: "LOGOUT",
  6: "FACTORY_RESET",
  7: "PIN_ATTEMPTS",
  8: "SET_CONFIGURATION",
  9: "GET_CONFIGURATION",
  10: "SET_PIN",
  11: "CHANGE_PIN",
  16: "INITIALIZE_SEED",
  17: "RESTORE_FROM_SEED",
  18: "GENERATE_KEY",
  19: "SIGN",
  20: "DECRYPT",
  21: "GENERATE_KEY_FROM_DATA",
  22: "GENERATE_RESIDENT_KEY",
  23: "READ_RESIDENT_KEY_PUBLIC",
  24: "DISCOVER_RESIDENT_KEYS",
  25: "WRITE_RESIDENT_KEY",
  32: "OPENPGP_DECRYPT",
  33: "OPENPGP_SIGN",
  34: "OPENPGP_INFO",
  35: "OPENPGP_IMPORT",
  36: "OPENPGP_INIT",
  254: "NOT_SET"
};
var string_to_command = Object.assign(
  {},
  ...Object.entries(command_to_string).map(
    ([a, b]) => ({ [b]: a })
  )
);
var ERROR_CBOR_PARSING = 16;

// js/helpers.ts
var TestError = class extends Error {
};
function TEST(tested_condition, test_description, logfn = async () => {
}) {
  if (tested_condition) {
    if (test_description) {
      const message = "+++ PASS: " + test_description;
      console.log(message);
      logfn(message);
    }
  } else {
    const message_fail = "--- TEST FAIL: " + test_description;
    console.log(message_fail);
    logfn(message_fail);
    throw new TestError(message_fail);
  }
}
function byteToHexString(uint8arr) {
  if (!uint8arr) {
    return "";
  }
  let hexStr = "";
  for (let i = 0; i < uint8arr.length; i++) {
    let hex = (uint8arr[i] & 255).toString(16);
    hex = hex.length === 1 ? "0" + hex : hex;
    hexStr += hex;
  }
  return hexStr.toUpperCase();
}
function hexStringToByte(str) {
  if (!str) {
    return new Uint8Array();
  }
  const a = [];
  for (let i = 0, len = str.length; i < len; i += 2) {
    a.push(parseInt(str.substr(i, 2), 16));
  }
  return new Uint8Array(a);
}
function uint8ToUint16(uint_arr, littleEndian = false) {
  return new DataView(uint_arr.buffer).getUint16(0, littleEndian);
}
function flatten(u8_arr_arr) {
  let s = 0;
  for (let i = 0; i < u8_arr_arr.length; i++) {
    s += u8_arr_arr[i].length;
  }
  let res = new Uint8Array(s);
  let offset = 0;
  for (let i = 0; i < u8_arr_arr.length; i++) {
    res.set(u8_arr_arr[i], offset);
    offset += u8_arr_arr[i].length;
  }
  return res;
}
function concat(a, b) {
  let c = new Uint8Array(a.length + b.length);
  c.set(a, 0);
  c.set(b, a.length);
  return c;
}
function int2arr(uint) {
  let uint_arr = new Uint8Array(1);
  uint_arr[0] = uint;
  return uint_arr;
}
function getBinaryStr(data) {
  let uintArray = new Uint8Array(data.length).fill(67);
  for (let i = 0; i < data.length; ++i) {
    uintArray[i] = data.charCodeAt(i);
  }
  return uintArray;
}
function dict_binval(dictionary) {
  let res = {};
  for (let i in dictionary) {
    if (typeof dictionary[i] === "object") {
      res[i] = dictionary[i];
    } else if (i === "PIN" || i === "NEWPIN") {
      res[i] = getBinaryStr(dictionary[i]);
    } else {
      res[i] = hexStringToByte(dictionary[i]);
    }
  }
  return res;
}
function dict_hexval(dictionary) {
  let res = {};
  for (let i in dictionary) {
    if (typeof dictionary[i] === "object") {
      res[i] = byteToHexString(dictionary[i]);
    } else {
      res[i] = dictionary[i];
    }
  }
  return res;
}
function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
async function generate_key_ecc() {
  const algorithm = {
    name: "ECDH",
    namedCurve: "P-256"
  };
  return await window.crypto.subtle.generateKey(
    algorithm,
    true,
    ["deriveKey"]
  );
}
async function agree_on_key(privateKey, publicKey) {
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
async function encode_text(text) {
  return new TextEncoder().encode(text);
}
async function encrypt_aes(key, data) {
  const encoded = data;
  const iv = new Uint8Array(16).fill(0);
  return window.crypto.subtle.encrypt(
    {
      name: "AES-CBC",
      iv,
      length: 256
    },
    key,
    encoded
  );
}
async function calculate_hmac(key_in, data) {
  const algorithm = { name: "HMAC", hash: "SHA-256" };
  const encoder = new TextEncoder();
  const keyraw = await export_key(key_in);
  const key = await crypto.subtle.importKey(
    "raw",
    keyraw,
    algorithm,
    true,
    ["sign", "verify"]
  );
  return await window.crypto.subtle.sign(
    "HMAC",
    key,
    data
  );
}
async function number_to_short(n) {
  const buffer = new ArrayBuffer(2);
  const dataView = new DataView(buffer);
  dataView.setInt16(0, n, true);
  return dataView.buffer;
}
async function ecdsa_to_ecdh(pk) {
  return await crypto.subtle.importKey(
    "raw",
    await crypto.subtle.exportKey("raw", pk),
    {
      name: "ecdh",
      namedCurve: "P-256"
    },
    true,
    []
  );
}
async function import_key(data) {
  const algorithm = {
    name: "ECDSA",
    namedCurve: "P-256"
  };
  return await crypto.subtle.importKey(
    "raw",
    data,
    algorithm,
    true,
    ["verify"]
  );
}
async function export_key(key) {
  const exported = await window.crypto.subtle.exportKey(
    "raw",
    key
  );
  return new Uint8Array(exported);
}
function buffer_to_uint8(buf) {
  return new Uint8Array(buf);
}
function round_to_next(x, n) {
  return x + n - x % n;
}
function pkcs7_pad_16(arr) {
  const s = arr.length;
  const s_pad = round_to_next(s, 16);
  const arr_padded = new Uint8Array(s_pad).fill(s_pad - s);
  arr_padded.set(arr);
  return arr_padded;
}

// js/ctaphid.ts
function encode_ctaphid_request_as_keyhandle(cmd, data) {
  if (VERBOSE)
    console.log("ctaphid REQUEST CMD", cmd, "(", command_codes[cmd], ")", data);
  data = data || new Uint8Array(16).fill(64);
  const offset = 5;
  if (offset + data.length > 255) {
    throw new Error("Max size exceeded");
  }
  const array = new Uint8Array(offset + data.length);
  array[0] = cmd & 255;
  array[1] = 140;
  array[2] = 39;
  array[3] = 144;
  array[4] = 246;
  array.set(data, offset);
  if (VERBOSE)
    console.log("ctaphid FORMATTED REQUEST:", array);
  return array;
}
function decode_ctaphid_response_from_signature(response) {
  const signature_count = new DataView(
    response.authenticatorData.slice(33, 37)
  ).getUint32(0, false);
  const signature = new Uint8Array(response.signature);
  let data = null;
  let error_code = null;
  if (signature.length > 0) {
    error_code = signature[0];
    if (error_code == 0) {
      data = signature.slice(1, signature.length);
    }
  }
  return {
    count: signature_count,
    status: "error_code",
    status_code: error_code,
    data,
    signature
  };
}
async function ctaphid_via_webauthn(cmd, data, timeout) {
  const keyhandle = encode_ctaphid_request_as_keyhandle(cmd, data);
  const challenge = new Uint8Array(32).fill(69);
  const request_options = {
    challenge,
    allowCredentials: [{
      id: keyhandle,
      type: "public-key"
    }],
    timeout,
    userVerification: "discouraged"
  };
  try {
    const result = await navigator.credentials.get({
      publicKey: request_options
    });
    const assertion = result;
    if (VERBOSE)
      console.log("ctaphid GOT ASSERTION", assertion);
    if (!assertion)
      throw new Error("Empty assertion");
    if (!assertion.response)
      throw new Error("Empty assertion response");
    if (VERBOSE)
      console.log("ctaphid RESPONSE", assertion.response);
    const response = decode_ctaphid_response_from_signature(assertion.response);
    if (VERBOSE)
      console.log("ctaphid RESPONSE decoded:", response);
    return response;
  } catch (error) {
    console.log(`ctaphid ERROR CALLING: ${cmd}/${command_codes[cmd]}`);
    console.log("ctaphid THE ERROR:", error);
    throw error;
    return Promise.resolve();
  }
}

// js/exceptions.ts
var CommandExecutionError = class extends Error {
  constructor(m, errcode) {
    super("CommandExecutionError - " + m + " - " + errcode_to_string[errcode] + " " + errcode.toString() + " hex: 0x" + errcode.toString(16));
    this.errcode = 0;
    this.name = "";
    Object.setPrototypeOf(this, CommandExecutionError.prototype);
    this.errcode = errcode;
    this.name = errcode_to_string[errcode];
  }
};

// js/logs.ts
var library_initialization_time_ms = Date.now();
function log_message_library(s, ...args) {
  s = prefix_with_timestamp(s, "*WC");
  args = [s].concat(args);
  console.log.apply(console, args);
}
function log_message(s) {
  s = prefix_with_timestamp(s);
  console.log(s);
  let logs = document.getElementById("console");
  if (logs) {
    logs.innerHTML = logs.innerHTML + s + "\r\n";
    logs.scrollTop = logs.scrollHeight;
  }
}
function prefix_with_timestamp(s, prefix = "*") {
  const time = ((Date.now() - library_initialization_time_ms) / 1e3).toFixed(1);
  s = `${prefix} [${time}] ` + s;
  return s;
}
async function log_fn(statusText) {
  log_function_library(statusText);
}
var log_function_library = (message) => log_message(message);

// js/transport.ts
function WEBCRYPT_get_protocol_header(op_type, packet_num, number_of_packets, this_chunk_length) {
  let data = new Uint8Array(5).fill(60);
  let op_type_str = "";
  let max_chunk_size = 0;
  if (op_type === 2 /* RECEIVE */) {
    max_chunk_size = WEBCRYPT_CONSTANTS.CHUNK_SIZE_RECEIVE;
    op_type_str = "RECEIVE";
  } else if (op_type === 1 /* SEND */) {
    max_chunk_size = WEBCRYPT_CONSTANTS.CHUNK_SIZE_SEND;
    op_type_str = "SEND";
  }
  if (this_chunk_length === void 0 || this_chunk_length === 0) {
    this_chunk_length = max_chunk_size;
  }
  data[0] = op_type & 255;
  data[1] = packet_num;
  data[2] = number_of_packets;
  data[3] = max_chunk_size;
  data[4] = this_chunk_length;
  if (VERBOSE)
    log_message_library(`Packet header ${op_type_str}: ${packet_num + 1}/${number_of_packets} [${packet_num * max_chunk_size},${(packet_num + 1) * max_chunk_size}), size: ${this_chunk_length}/${max_chunk_size}`);
  return data;
}
function get_data_length_from_the_first_packet(data) {
  return uint8ToUint16(data.slice(0, 2));
}
async function WEBCRYPT_receive(cmd) {
  let received_data_arr = [];
  const cmda = int2arr(cmd);
  let dataLen = 0;
  const number_of_packets = Math.ceil(WEBCRYPT_CONSTANTS.BUFFER_SIZE / WEBCRYPT_CONSTANTS.CHUNK_SIZE_RECEIVE);
  for (let packet_no = 0; packet_no < number_of_packets; packet_no++) {
    if (packet_no > 0 && dataLen < packet_no * WEBCRYPT_CONSTANTS.CHUNK_SIZE_RECEIVE) {
      break;
    }
    const header_data = WEBCRYPT_get_protocol_header(2 /* RECEIVE */, packet_no, number_of_packets);
    const data_to_send = concat(header_data, cmda);
    try {
      const response = await ctaphid_via_webauthn(34 /* WEBCRYPT */, data_to_send, WEBCRYPT_CONSTANTS.TIMEOUT);
      received_data_arr.push(response.signature);
      if (VERBOSE)
        log_message_library("WC_receive RESPONSE", response);
      if (packet_no === 0 && response.data_len !== null) {
        dataLen = get_data_length_from_the_first_packet(response.signature);
      }
    } catch (error) {
      log_message_library("WC_receive ERROR", error);
      throw error;
    }
  }
  let received_data = flatten(received_data_arr);
  const commandID = received_data[2];
  received_data = received_data.slice(3, dataLen);
  console.log("Received data complete", received_data, received_data_arr);
  if (VERBOSE)
    log_message_library(`WEBCRYPT_receive received_data - len:${dataLen}, cmd:${commandID}, data:`, received_data);
  return received_data;
}
async function WEBCRYPT_send(cmd, data_to_send) {
  let written_packets_data = [];
  let responses = [];
  let error_flag = false;
  const data_to_send_orig = data_to_send;
  data_to_send = prepare_data_to_send(cmd, data_to_send);
  if (VERBOSE)
    log_message_library(`WC_send cmd:${cmd}, data_to_send - orig and final`, data_to_send_orig, data_to_send);
  const number_of_packets = Math.ceil(data_to_send.length / WEBCRYPT_CONSTANTS.CHUNK_SIZE_SEND);
  for (let i = 0; i < number_of_packets; i++) {
    const data_chunk = data_to_send.slice(i * WEBCRYPT_CONSTANTS.CHUNK_SIZE_SEND, (i + 1) * WEBCRYPT_CONSTANTS.CHUNK_SIZE_SEND);
    TEST(data_chunk.length > 0, "Data to send not null");
    const header_data = WEBCRYPT_get_protocol_header(1 /* SEND */, i, number_of_packets, data_chunk.length);
    let final_packet_data = add_packet_header_to_data(header_data, data_chunk);
    written_packets_data.push(final_packet_data);
    let code = 0;
    try {
      if (VERBOSE)
        log_message_library(`Sending packet ${i + 1}/${number_of_packets} [${i * WEBCRYPT_CONSTANTS.CHUNK_SIZE_SEND},${(i + 1) * WEBCRYPT_CONSTANTS.CHUNK_SIZE_SEND}), size: ${data_chunk.length}/${WEBCRYPT_CONSTANTS.CHUNK_SIZE_SEND} (t:${final_packet_data.length})`);
      const response = await ctaphid_via_webauthn(34 /* WEBCRYPT */, final_packet_data, WEBCRYPT_CONSTANTS.TIMEOUT);
      if (VERBOSE)
        log_message_library("WC_send RESPONSE", response);
      responses.push(response.data);
      code = response.status_code;
      if (response && code !== 0) {
        log_message_library("WC_send ERROR", response, code);
        log_message_library("Error: ", errcode_to_string[code], code, "hex: 0x" + code.toString(16));
        error_flag = true;
      }
    } catch (_e) {
      log_message_library("WC_send ERROR other", _e);
      throw _e;
    }
    if (error_flag) {
      log_message_library("WC_send breaking due to an error");
      log_message_library("WC_send responses status", responses);
      log_message_library("WC_send written_data status", written_packets_data);
      if (code === ERROR_CBOR_PARSING) {
        log_message_library("CBOR failed with:", data_to_send_orig, "transformed to: ", data_to_send);
      }
      throw new CommandExecutionError("Command failed", code);
    }
  }
  return !error_flag;
}
function add_packet_header_to_data(header_data, data_chunk) {
  let data = new Uint8Array(header_data.length + data_chunk.length).fill(63);
  data.set(header_data, 0);
  data.set(data_chunk, header_data.length);
  const comm_offset = WEBCRYPT_CONSTANTS.COMM_OFFSET;
  let final_data = new Uint8Array(comm_offset + data.length).fill(66);
  final_data.set(data, comm_offset);
  return final_data;
}
function prepare_data_to_send(cmd, data_to_send) {
  const _padding = new Uint8Array(2).fill(255);
  let cmdarr = int2arr(cmd);
  cmdarr = concat(_padding, cmdarr);
  data_to_send = concat(cmdarr, data_to_send);
  return data_to_send;
}
function cbor_encode(data) {
  const arrbuf = CBOR.encode(data);
  return new Uint8Array(arrbuf);
}
function lib_delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
async function repeat_wrapper(func, action, statusCallback) {
  const total_attempts = 20;
  for (let attempt = 0; attempt < total_attempts; attempt++) {
    try {
      const attemptText = `Attempting to run command (${action}). Please press the touch button to confirm command.`;
      await statusCallback(attemptText);
      log_message(attemptText);
      await func();
      const successText = `Action (${action}) executed successfully.`;
      await statusCallback(successText);
      log_message(successText);
      return;
    } catch (e) {
      if (e instanceof CommandExecutionError && e.name === "ERR_USER_NOT_PRESENT" && attempt !== total_attempts - 1) {
        const retryText = `Failed Attempt. Retrying... Please press the touch button to confirm command (${action}) (${attempt + 1}/${total_attempts} attempts).`;
        await statusCallback(retryText);
        log_message(retryText);
        await lib_delay(1e3);
        continue;
      }
      const failureText = `Action (${action}) failed. Error: ${e}`;
      await statusCallback(failureText);
      log_message(failureText);
      throw e;
    }
  }
}
var lockify = (f) => {
  let lock = Promise.resolve();
  return (...params) => {
    const result = lock.then(() => f(...params));
    lock = result.catch(() => {
    });
    return result.then((value) => value);
  };
};
var send_command_locked = lockify(_send_command);
async function send_command(token, cmd, data = {}, statusCallback) {
  log_message_library("Making lock");
  const res = await send_command_locked(token, cmd, data, statusCallback);
  log_message_library("Releasing lock");
  return res;
}
async function _send_command(token, cmd, data = {}, statusCallback) {
  data = dict_binval(data);
  if (cmd === 5 /* LOGOUT */) {
    token.clear();
  } else if (cmd !== 4 /* LOGIN */) {
    data = token.authorize(data);
  }
  if (VERBOSE)
    log_message_library(`send_command, cmd:${cmd}, data:`, data);
  console.log("final data sent", data);
  data = cbor_encode(data);
  try {
    await lib_delay(100);
    await repeat_wrapper(() => WEBCRYPT_send(cmd, data), command_to_string[cmd], statusCallback);
  } catch (error) {
    throw error;
  }
  await lib_delay(100);
  const response_cbor = await WEBCRYPT_receive(cmd);
  if (response_cbor.length == 0) {
    if (VERBOSE)
      log_message_library(`send_command finished, cmd:${cmd}`);
    return {};
  }
  const result = CBOR.decode(response_cbor.buffer);
  if (VERBOSE)
    log_message_library(`send_command finished, cmd:${cmd}, result:`, result);
  return dict_hexval(result);
}

// js/session.ts
var Session = class {
  constructor() {
    this.validPeriod = 6e4;
    this.TP = "";
    this.validUntil = 0;
    this.TP = "";
  }
  clear() {
    this.TP = "";
  }
  get token() {
    return this.TP;
  }
  getSecondsEpoch() {
    return new Date().getTime() / 1e3;
  }
  set token(token) {
    log_message_library(`Auth token set: '${token.slice(0, 4).toString()}'`);
    this.TP = token;
    this.validUntil = this.getSecondsEpoch() + this.validPeriod;
  }
  timeLeft() {
    if (!this.valid())
      return 0;
    return this.validUntil - this.getSecondsEpoch();
  }
  valid() {
    return this.getSecondsEpoch() < this.validUntil && this.TP !== void 0 && this.TP.length !== 0;
  }
  authorize(data) {
    log_message_library(`Auth token '${this.TP.slice(0, 4).toString()}' valid for the next ${this.timeLeft().toFixed(1)} seconds`);
    if (!this.valid()) {
      if (this.validUntil !== 0)
        console.warn("Temporary authorization token is not valid anymore. Clearing state.");
      this.clear();
    }
    if (!data) {
      data = {};
    }
    data["TP"] = new Uint8Array(4);
    return data;
  }
};

// js/types.ts
var WCKeyDetails = class {
  constructor(pk, kh) {
    this.keyhandle = kh;
    this.pubkey = pk;
  }
};

// js/commands.ts
var session = new Session();
var CommandStatusReturn = class {
  constructor(UNLOCKED, VERSION, SLOTS, PIN_ATTEMPTS) {
    this.UNLOCKED = UNLOCKED;
    this.VERSION = VERSION;
    this.SLOTS = SLOTS;
    this.PIN_ATTEMPTS = PIN_ATTEMPTS;
  }
};
async function Webcrypt_Status(statusCallback) {
  const res = await send_command(session, 0 /* STATUS */, {}, statusCallback);
  return new CommandStatusReturn(res["UNLOCKED"], res["VERSION"], res["SLOTS"], res["PIN_ATTEMPTS"]);
}
var CommandTestPingParams = class {
  constructor(WebcryptData2) {
    this.WebcryptData = WebcryptData2;
  }
};
var CommandTestPingReturn = class {
  constructor(WebcryptData2) {
    this.WebcryptData = WebcryptData2;
  }
};
async function Webcrypt_TestPing(statusCallback, data) {
  const res = await send_command(session, 1 /* TEST_PING */, data, statusCallback);
  return new CommandTestPingReturn(res["WebcryptData"]);
}
async function Webcrypt_TestClear(statusCallback) {
  const res = await send_command(session, 2 /* TEST_CLEAR */, {}, statusCallback);
}
async function Webcrypt_TestReboot(statusCallback) {
  const res = await send_command(session, 3 /* TEST_REBOOT */, {}, statusCallback);
}
var CommandLoginParams = class {
  constructor(PIN) {
    this.PIN = PIN;
  }
};
var CommandLoginReturn = class {
  constructor(TP) {
    this.TP = TP;
  }
};
async function Webcrypt_Login(statusCallback, data) {
  const res = await send_command(session, 4 /* LOGIN */, data, statusCallback);
  return new CommandLoginReturn(res["TP"]);
}
async function Webcrypt_Logout(statusCallback) {
  const res = await send_command(session, 5 /* LOGOUT */, {}, statusCallback);
}
async function Webcrypt_FactoryReset(statusCallback) {
  const res = await send_command(session, 6 /* FACTORY_RESET */, {}, statusCallback);
}
var CommandSetConfigurationParams = class {
  constructor(CONFIRMATION) {
    this.CONFIRMATION = CONFIRMATION;
  }
};
async function Webcrypt_SetConfiguration(statusCallback, data) {
  const res = await send_command(session, 8 /* SET_CONFIGURATION */, data, statusCallback);
}
var CommandGetConfigurationReturn = class {
  constructor(CONFIRMATION) {
    this.CONFIRMATION = CONFIRMATION;
  }
};
async function Webcrypt_GetConfiguration(statusCallback) {
  const res = await send_command(session, 9 /* GET_CONFIGURATION */, {}, statusCallback);
  return new CommandGetConfigurationReturn(res["CONFIRMATION"]);
}
var CommandSetPinParams = class {
  constructor(PIN) {
    this.PIN = PIN;
  }
};
async function Webcrypt_SetPin(statusCallback, data) {
  const res = await send_command(session, 10 /* SET_PIN */, data, statusCallback);
}
var CommandChangePinParams = class {
  constructor(PIN, NEWPIN) {
    this.PIN = PIN;
    this.NEWPIN = NEWPIN;
  }
};
async function Webcrypt_ChangePin(statusCallback, data) {
  const res = await send_command(session, 11 /* CHANGE_PIN */, data, statusCallback);
}
var CommandInitializeSeedParams = class {
  constructor(ENTROPY) {
    this.ENTROPY = ENTROPY;
  }
};
var CommandInitializeSeedReturn = class {
  constructor(MASTER, SALT) {
    this.MASTER = MASTER;
    this.SALT = SALT;
  }
};
async function Webcrypt_InitializeSeed(statusCallback, data) {
  const res = await send_command(session, 16 /* INITIALIZE_SEED */, data, statusCallback);
  return new CommandInitializeSeedReturn(res["MASTER"], res["SALT"]);
}
var CommandRestoreFromSeedParams = class {
  constructor(MASTER, SALT) {
    this.MASTER = MASTER;
    this.SALT = SALT;
  }
};
var CommandRestoreFromSeedReturn = class {
  constructor(HASH) {
    this.HASH = HASH;
  }
};
async function Webcrypt_RestoreFromSeed(statusCallback, data) {
  const res = await send_command(session, 17 /* RESTORE_FROM_SEED */, data, statusCallback);
  return new CommandRestoreFromSeedReturn(res["HASH"]);
}
var CommandGenerateKeyReturn = class {
  constructor(PUBKEY, KEYHANDLE) {
    this.PUBKEY = PUBKEY;
    this.KEYHANDLE = KEYHANDLE;
  }
};
async function Webcrypt_GenerateKey(statusCallback) {
  const res = await send_command(session, 18 /* GENERATE_KEY */, {}, statusCallback);
  return new CommandGenerateKeyReturn(res["PUBKEY"], res["KEYHANDLE"]);
}
var CommandSignParams = class {
  constructor(HASH, KEYHANDLE) {
    this.HASH = HASH;
    this.KEYHANDLE = KEYHANDLE;
  }
};
var CommandSignReturn = class {
  constructor(SIGNATURE, INHASH) {
    this.SIGNATURE = SIGNATURE;
    this.INHASH = INHASH;
  }
};
async function Webcrypt_Sign(statusCallback, data) {
  const res = await send_command(session, 19 /* SIGN */, data, statusCallback);
  return new CommandSignReturn(res["SIGNATURE"], res["INHASH"]);
}
var CommandDecryptParams = class {
  constructor(DATA, KEYHANDLE, HMAC, ECCEKEY) {
    this.DATA = DATA;
    this.KEYHANDLE = KEYHANDLE;
    this.HMAC = HMAC;
    this.ECCEKEY = ECCEKEY;
  }
};
var CommandDecryptReturn = class {
  constructor(DATA) {
    this.DATA = DATA;
  }
};
async function Webcrypt_Decrypt(statusCallback, data) {
  const res = await send_command(session, 20 /* DECRYPT */, data, statusCallback);
  return new CommandDecryptReturn(res["DATA"]);
}
var CommandGenerateKeyFromDataParams = class {
  constructor(HASH) {
    this.HASH = HASH;
  }
};
var CommandGenerateKeyFromDataReturn = class {
  constructor(PUBKEY, KEYHANDLE) {
    this.PUBKEY = PUBKEY;
    this.KEYHANDLE = KEYHANDLE;
  }
};
async function Webcrypt_GenerateKeyFromData(statusCallback, data) {
  const res = await send_command(session, 21 /* GENERATE_KEY_FROM_DATA */, data, statusCallback);
  return new CommandGenerateKeyFromDataReturn(res["PUBKEY"], res["KEYHANDLE"]);
}
var CommandGenerateResidentKeyReturn = class {
  constructor(PUBKEY, KEYHANDLE) {
    this.PUBKEY = PUBKEY;
    this.KEYHANDLE = KEYHANDLE;
  }
};
async function Webcrypt_GenerateResidentKey(statusCallback) {
  const res = await send_command(session, 22 /* GENERATE_RESIDENT_KEY */, {}, statusCallback);
  return new CommandGenerateResidentKeyReturn(res["PUBKEY"], res["KEYHANDLE"]);
}
var CommandReadResidentKeyPublicParams = class {
  constructor(KEYHANDLE) {
    this.KEYHANDLE = KEYHANDLE;
  }
};
var CommandReadResidentKeyPublicReturn = class {
  constructor(PUBKEY, KEYHANDLE) {
    this.PUBKEY = PUBKEY;
    this.KEYHANDLE = KEYHANDLE;
  }
};
async function Webcrypt_ReadResidentKeyPublic(statusCallback, data) {
  const res = await send_command(session, 23 /* READ_RESIDENT_KEY_PUBLIC */, data, statusCallback);
  return new CommandReadResidentKeyPublicReturn(res["PUBKEY"], res["KEYHANDLE"]);
}
async function Webcrypt_DiscoverResidentKeys(statusCallback) {
  const res = await send_command(session, 24 /* DISCOVER_RESIDENT_KEYS */, {}, statusCallback);
}
var CommandWriteResidentKeyParams = class {
  constructor(RAW_KEY_DATA) {
    this.RAW_KEY_DATA = RAW_KEY_DATA;
  }
};
var CommandWriteResidentKeyReturn = class {
  constructor(PUBKEY, KEYHANDLE) {
    this.PUBKEY = PUBKEY;
    this.KEYHANDLE = KEYHANDLE;
  }
};
async function Webcrypt_WriteResidentKey(statusCallback, data) {
  const res = await send_command(session, 25 /* WRITE_RESIDENT_KEY */, data, statusCallback);
  return new CommandWriteResidentKeyReturn(res["PUBKEY"], res["KEYHANDLE"]);
}

// js/webcrypt.ts
var session2 = new Session();
async function WEBCRYPT_STATUS(statusCallback) {
  return await send_command(session2, 0 /* STATUS */, {}, statusCallback);
}
async function WEBCRYPT_LOGIN(PIN, statusCallback) {
  const data = { "PIN": PIN };
  let result = {};
  let err = 0;
  const total_attempts = 5;
  for (let i = 0; i < total_attempts; i++) {
    try {
      if (VERBOSE)
        console.log("Please press the touch button to continue");
      await log_fn(`Login attempt: ${i + 1}/${total_attempts}`);
      result = await send_command(session2, 4 /* LOGIN */, data, statusCallback);
      err = 0;
      break;
    } catch (error) {
      if (error instanceof CommandExecutionError && i < total_attempts - 1) {
        if (error.errcode !== string_to_errcode["ERR_USER_NOT_PRESENT"]) {
          await log_fn(`Error encountered: ${error.name}`);
          throw error;
        }
        if (VERBOSE)
          console.log("error", error);
        err = error;
        await delay(1e3);
        await log_fn("User touch not registered. Trying to log in one more time.");
      } else {
        throw error;
      }
    }
  }
  if (err) {
    await log_fn("User touch not registered. Throwing exception.");
    throw err;
  }
  session2.token = result["TP"];
  await log_fn("User touch registered. Logged in.");
}
async function WEBCRYPT_GENERATE_FROM_DATA(statusCallback, data) {
  const data_to_send = { "HASH": data };
  try {
    const res = await send_command(session2, 21 /* GENERATE_KEY_FROM_DATA */, data_to_send, statusCallback);
    const pk = res["PUBKEY"];
    return new WCKeyDetails(pk, res["KEYHANDLE"]);
  } catch (e) {
    console.log(e);
  }
  return new WCKeyDetails("", "");
}
async function WEBCRYPT_GENERATE(statusCallback) {
  const res = await send_command(session2, 18 /* GENERATE_KEY */, null, statusCallback);
  const pk = res["PUBKEY"];
  return new WCKeyDetails(pk, res["KEYHANDLE"]);
}
async function WEBCRYPT_SIGN(statusCallback, hash, key_handle) {
  const data_to_send = { "HASH": hash, "KEYHANDLE": key_handle };
  const res = await send_command(session2, 19 /* SIGN */, data_to_send, statusCallback);
  return res["SIGNATURE"];
}
async function WEBCRYPT_ENCRYPT(statusCallback, data_to_encrypt, pubkey_hex, keyhandle_hex) {
  const plaintext = await encode_text(data_to_encrypt);
  const plaintext_with_len = flatten([buffer_to_uint8(await number_to_short(plaintext.length)), plaintext]);
  const plaintext_pad = pkcs7_pad_16(plaintext_with_len);
  const pubkey_raw = hexStringToByte(pubkey_hex);
  const pubkey = await import_key(pubkey_raw);
  const pubkey_ecdh = await ecdsa_to_ecdh(pubkey);
  const keyhandle = hexStringToByte(keyhandle_hex);
  const ephereal_keypair = await generate_key_ecc();
  const ephereal_pubkey = ephereal_keypair.publicKey;
  const ephereal_pubkey_raw = await export_key(ephereal_pubkey);
  const aes_key = await agree_on_key(ephereal_keypair.privateKey, pubkey_ecdh);
  const ciphertext = await encrypt_aes(aes_key, plaintext_pad);
  const ciphertext_len = await number_to_short(ciphertext.byteLength);
  const data_to_hmac = flatten([
    buffer_to_uint8(ciphertext),
    ephereal_pubkey_raw,
    buffer_to_uint8(ciphertext_len),
    keyhandle
  ]);
  const hmac = await calculate_hmac(aes_key, data_to_hmac);
  return new CommandDecryptParams(
    byteToHexString(buffer_to_uint8(ciphertext)),
    byteToHexString(keyhandle),
    byteToHexString(buffer_to_uint8(hmac)),
    byteToHexString(ephereal_pubkey_raw)
  );
}
async function WEBCRYPT_VERIFY(statusCallback, pubkey_hex, signature_hex, hash_hex) {
  const algorithm = {
    name: "ECDSA",
    hash: { name: "SHA-256" },
    namedCurve: "P-256"
  };
  try {
    const publicKey = await crypto.subtle.importKey(
      "raw",
      hexStringToByte(pubkey_hex),
      algorithm,
      true,
      ["verify"]
    );
    const signature = hexStringToByte(signature_hex);
    const encoded = hexStringToByte(hash_hex);
    const verify_res = await window.crypto.subtle.verify(
      algorithm,
      publicKey,
      signature,
      encoded
    );
    console.log("Verify result", { pubkey_hex, signature_hex, hash_hex, verify_res, publicKey });
    return verify_res;
  } catch (e) {
    console.log("fail", e);
    return false;
  }
}
async function WEBCRYPT_OPENPGP_DECRYPT(statusCallback, eccekey) {
  const data_to_send = { "ECCEKEY": eccekey };
  const res = await send_command(session2, 32 /* OPENPGP_DECRYPT */, data_to_send, statusCallback);
  return hexStringToByte(res["DATA"]);
}
async function WEBCRYPT_OPENPGP_SIGN(statusCallback, data) {
  const data_to_send = { "DATA": data };
  const res = await send_command(session2, 33 /* OPENPGP_SIGN */, data_to_send, statusCallback);
  return res["SIGNATURE"];
}
async function WEBCRYPT_OPENPGP_INFO(statusCallback) {
  const res = await send_command(session2, 34 /* OPENPGP_INFO */, {}, statusCallback);
  const sign_pubkey = concat(new Uint8Array([4]), hexStringToByte(res["SIGN_PUBKEY"]));
  const encr_pubkey = concat(new Uint8Array([4]), hexStringToByte(res["ENCR_PUBKEY"]));
  const dateB = hexStringToByte(res["DATE"]);
  const dateS = new TextDecoder().decode(dateB);
  const date = Number(dateS);
  console.log({ encr_pubkey, sign_pubkey, date, name: "webcrypt openpgp info result" });
  return { encr_pubkey, sign_pubkey, date };
}
async function WEBCRYPT_OPENPGP_IMPORT(statusCallback, {
  encr_privkey = null,
  sign_privkey = null,
  auth_privkey = null,
  date = new Date(),
  ...rest
}) {
  const data = {
    "ENCR_PRIVKEY": encr_privkey ? byteToHexString(encr_privkey) : "",
    "SIGN_PRIVKEY": sign_privkey ? byteToHexString(sign_privkey) : "",
    "AUTH_PRIVKEY": auth_privkey ? byteToHexString(auth_privkey) : sign_privkey ? byteToHexString(sign_privkey) : "",
    "DATE": byteToHexString(new TextEncoder().encode(date.getTime().toString()))
  };
  await send_command(session2, 35 /* OPENPGP_IMPORT */, data, statusCallback);
}
async function WEBCRYPT_OPENPGP_GENERATE(statusCallback) {
  await send_command(session2, 36 /* OPENPGP_GENERATE */, {}, statusCallback);
}
export {
  CommandChangePinParams,
  CommandDecryptParams,
  CommandDecryptReturn,
  CommandGenerateKeyFromDataParams,
  CommandGenerateKeyFromDataReturn,
  CommandGenerateKeyReturn,
  CommandGenerateResidentKeyReturn,
  CommandGetConfigurationReturn,
  CommandInitializeSeedParams,
  CommandInitializeSeedReturn,
  CommandLoginParams,
  CommandLoginReturn,
  CommandReadResidentKeyPublicParams,
  CommandReadResidentKeyPublicReturn,
  CommandRestoreFromSeedParams,
  CommandRestoreFromSeedReturn,
  CommandSetConfigurationParams,
  CommandSetPinParams,
  CommandSignParams,
  CommandSignReturn,
  CommandStatusReturn,
  CommandTestPingParams,
  CommandTestPingReturn,
  CommandWriteResidentKeyParams,
  CommandWriteResidentKeyReturn,
  WEBCRYPT_ENCRYPT,
  WEBCRYPT_GENERATE,
  WEBCRYPT_GENERATE_FROM_DATA,
  WEBCRYPT_LOGIN,
  WEBCRYPT_OPENPGP_DECRYPT,
  WEBCRYPT_OPENPGP_GENERATE,
  WEBCRYPT_OPENPGP_IMPORT,
  WEBCRYPT_OPENPGP_INFO,
  WEBCRYPT_OPENPGP_SIGN,
  WEBCRYPT_SIGN,
  WEBCRYPT_STATUS,
  WEBCRYPT_VERIFY,
  Webcrypt_ChangePin,
  Webcrypt_Decrypt,
  Webcrypt_DiscoverResidentKeys,
  Webcrypt_FactoryReset,
  Webcrypt_GenerateKey,
  Webcrypt_GenerateKeyFromData,
  Webcrypt_GenerateResidentKey,
  Webcrypt_GetConfiguration,
  Webcrypt_InitializeSeed,
  Webcrypt_Login,
  Webcrypt_Logout,
  Webcrypt_ReadResidentKeyPublic,
  Webcrypt_RestoreFromSeed,
  Webcrypt_SetConfiguration,
  Webcrypt_SetPin,
  Webcrypt_Sign,
  Webcrypt_Status,
  Webcrypt_TestClear,
  Webcrypt_TestPing,
  Webcrypt_TestReboot,
  Webcrypt_WriteResidentKey,
  byteToHexString,
  hexStringToByte
};
//# sourceMappingURL=webcrypt.min.mjs.map
