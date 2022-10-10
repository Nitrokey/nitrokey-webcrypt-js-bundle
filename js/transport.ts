// Copyright 2022 Nitrokey GmbH
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


/// <reference path="cbor.d.ts" />

// @ts-ignore
import * as CBOR from './vendor/cbor.js';

import {
  CMD,
  command_to_string,
  WEBCRYPT_CMD,
  WEBCRYPT_CONSTANTS,
  WEBCRYPT_DEVICE_COMM,
  errcode_to_string,
  ERROR_CBOR_PARSING,
  VERBOSE
} from './constants';
import {concat, dict_binval, dict_hexval, flatten, int2arr, TEST, uint8ToUint16} from "./helpers"
import {ctaphid_via_webauthn} from "./ctaphid"
import {CommandExecutionError} from "./exceptions"
// import {gather_platform_info} from "./platform";

import {Session} from "./session";
import {log_message, log_message_library} from "./logs";
import {StatusCallback} from "./types";


function WEBCRYPT_get_protocol_header(op_type: WEBCRYPT_DEVICE_COMM, packet_num: number, number_of_packets: number,
                                this_chunk_length?: number): Uint8Array {
  let data = new Uint8Array(5).fill(60);

  let op_type_str = '';
  let max_chunk_size = 0;
  if (op_type === WEBCRYPT_DEVICE_COMM.RECEIVE) {
    max_chunk_size = WEBCRYPT_CONSTANTS.CHUNK_SIZE_RECEIVE;
    op_type_str = 'RECEIVE';
  } else if (op_type === WEBCRYPT_DEVICE_COMM.SEND) {
    max_chunk_size = WEBCRYPT_CONSTANTS.CHUNK_SIZE_SEND;
    op_type_str = 'SEND';
  }

  if (this_chunk_length === undefined || this_chunk_length === 0){
    this_chunk_length = max_chunk_size;
  }

  data[0] = op_type & 0xff;
  data[1] = packet_num;
  data[2] = number_of_packets;
  data[3] = max_chunk_size;
  data[4] = this_chunk_length;

  if (VERBOSE) log_message_library(`Packet header ${op_type_str}: ${packet_num+1}/${number_of_packets} [${packet_num * max_chunk_size},${(packet_num + 1) * max_chunk_size}), size: ${this_chunk_length}/${max_chunk_size}`);

  return data;
}


function get_data_length_from_the_first_packet(data: Uint8Array): number {
  return uint8ToUint16(data.slice(0,2)); // uint16_t BE
}

export async function WEBCRYPT_receive(cmd: WEBCRYPT_CMD): Promise<Uint8Array> {
  let received_data_arr = [];
  const cmda = int2arr(cmd);

  let dataLen = 0;
  const number_of_packets = Math.ceil(WEBCRYPT_CONSTANTS.BUFFER_SIZE / WEBCRYPT_CONSTANTS.CHUNK_SIZE_RECEIVE);
  for (let packet_no = 0; packet_no < number_of_packets; packet_no++) {
    if (packet_no > 0 && dataLen < packet_no * WEBCRYPT_CONSTANTS.CHUNK_SIZE_RECEIVE) {
      break;
    }
    const header_data = WEBCRYPT_get_protocol_header(WEBCRYPT_DEVICE_COMM.RECEIVE, packet_no, number_of_packets);
    const data_to_send = concat(header_data, cmda);

    try{
      const response = await ctaphid_via_webauthn(CMD.WEBCRYPT, data_to_send, WEBCRYPT_CONSTANTS.TIMEOUT);
      received_data_arr.push(response.signature);
      if (VERBOSE) log_message_library("WC_receive RESPONSE", response);
      if (packet_no === 0 && response.data_len !== null) {
        dataLen = get_data_length_from_the_first_packet(response.signature);
      }
    }
    catch (error){
      log_message_library("WC_receive ERROR", error);
      throw error;
    }
  }

  let received_data = flatten(received_data_arr);
  const commandID = received_data[2];
  received_data = received_data.slice(3, dataLen);
  console.log("Received data complete",received_data, received_data_arr);

  if (VERBOSE) log_message_library(`WEBCRYPT_receive received_data - len:${dataLen}, cmd:${commandID}, data:`, received_data);
  return received_data;
}

export async function WEBCRYPT_send(cmd: WEBCRYPT_CMD, data_to_send: Uint8Array) {
  let written_packets_data = [];

  let responses: any[] = [];
  let error_flag: boolean = false;

  const data_to_send_orig = data_to_send;
  data_to_send = prepare_data_to_send(cmd, data_to_send);
  if (VERBOSE) log_message_library(`WC_send cmd:${cmd}, data_to_send - orig and final`, data_to_send_orig, data_to_send);

  const number_of_packets = Math.ceil(data_to_send.length / WEBCRYPT_CONSTANTS.CHUNK_SIZE_SEND);
  for (let i = 0; i < number_of_packets; i++) {
    const data_chunk = data_to_send.slice(i * WEBCRYPT_CONSTANTS.CHUNK_SIZE_SEND, (i + 1) * WEBCRYPT_CONSTANTS.CHUNK_SIZE_SEND);
    TEST(data_chunk.length > 0, 'Data to send not null');

    const header_data = WEBCRYPT_get_protocol_header(WEBCRYPT_DEVICE_COMM.SEND, i, number_of_packets, data_chunk.length);
    let final_packet_data = add_packet_header_to_data(header_data, data_chunk);

    written_packets_data.push(final_packet_data);
    let code: number = 0;
    try {
      if (VERBOSE) log_message_library(`Sending packet ${i+1}/${number_of_packets} [${i * WEBCRYPT_CONSTANTS.CHUNK_SIZE_SEND},${(i + 1) * WEBCRYPT_CONSTANTS.CHUNK_SIZE_SEND}), size: ${data_chunk.length}/${WEBCRYPT_CONSTANTS.CHUNK_SIZE_SEND} (t:${final_packet_data.length})`);

      const response = await ctaphid_via_webauthn(CMD.WEBCRYPT, final_packet_data, WEBCRYPT_CONSTANTS.TIMEOUT);
      if (VERBOSE) log_message_library("WC_send RESPONSE", response);
      responses.push(response.data);
      code = response.status_code;
      if (response && code !== 0) {
        log_message_library("WC_send ERROR", response, code);
        log_message_library("Error: ", errcode_to_string[code], code, 'hex: 0x' + code.toString(16));
        error_flag = true;
      }
    }
    catch (_e) {
      log_message_library("WC_send ERROR other", _e);
      throw _e;
    }
    if (error_flag) {
      log_message_library("WC_send breaking due to an error");
      log_message_library("WC_send responses status", responses);
      log_message_library("WC_send written_data status", written_packets_data);
      if (code === ERROR_CBOR_PARSING) {
        log_message_library('CBOR failed with:', data_to_send_orig, 'transformed to: ', data_to_send);
      }
      throw new CommandExecutionError('Command failed', code);
    }
  }
  return !error_flag;
}



function add_packet_header_to_data(header_data: Uint8Array, data_chunk: Uint8Array) {
  let data = new Uint8Array(header_data.length + data_chunk.length).fill(63);
  data.set(header_data, 0);
  data.set(data_chunk, header_data.length);
  const comm_offset = WEBCRYPT_CONSTANTS.COMM_OFFSET;
  let final_data = new Uint8Array(comm_offset + data.length).fill(66);
  final_data.set(data, comm_offset);
  return final_data;
}

function prepare_data_to_send(cmd: WEBCRYPT_CMD, data_to_send: Uint8Array) {
  /**
   * Add 2 chars left padding, and cmd id
   */
  const _padding = new Uint8Array(2).fill(0xFF);
  let cmdarr = int2arr(cmd);
  cmdarr = concat(_padding, cmdarr);
  data_to_send = concat(cmdarr, data_to_send);
  return data_to_send;
}

export function CBOR_encode_uint8t(data: any) {
  return new Uint8Array(CBOR.encode(data));
}

export function toString(arr: Uint8Array): string {
  let str = "";
  for (let i = 0; i < arr.length; ++i) {
    str += String.fromCharCode(arr[i]);
  }
  return str;
}


export function cbor_encode(data: any): Uint8Array {
  const arrbuf = CBOR.encode(data);
  return new Uint8Array(arrbuf);
}

function lib_delay(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function repeat_wrapper(func: Function, action: string, statusCallback: StatusCallback ){
  //TODO add callback function handling for UI interaction
  const total_attempts = 20;
  for (let attempt = 0; attempt<total_attempts; attempt++){
    try{
      const attemptText = `Attempting to run command (${action}). Please press the touch button to confirm command.`;
      await statusCallback(attemptText);
      log_message(attemptText);
      await func();
      const successText = `Action (${action}) executed successfully.`;
      await statusCallback(successText);
      log_message(successText);
      return;
    }
    catch (e) {
      if (e instanceof CommandExecutionError && e.name === "ERR_USER_NOT_PRESENT" && attempt !== total_attempts-1){
        const retryText = `Failed Attempt. Retrying... Please press the touch button to confirm command (${action}) (${attempt+1}/${total_attempts} attempts).`;
        await statusCallback(retryText);
        log_message(retryText);
        await lib_delay(1000);
        continue;
      }
      const failureText = `Action (${action}) failed. Error: ${e}`;
      await statusCallback(failureText);
      log_message(failureText);
      throw e;
    }
  }
}

// https://blog.testdouble.com/posts/2019-05-14-locking-with-promises/
// https://github.com/testdouble/lockify/blob/main/lib/lockify.js
// "license": "ISC",
// @ts-ignore
const lockify = f => {
  let lock = Promise.resolve()

  // @ts-ignore
  return (...params) => {
    const result = lock.then(() => f(...params))
    lock = result.catch(() => {})

    return result.then(value => value)
  }
}

// export async function send_command(token: Session, cmd: WEBCRYPT_CMD, data: any = {}, statusCallback:StatusCallback): Promise<any> {
const send_command_locked = lockify(_send_command);

export async function send_command(token: Session, cmd: WEBCRYPT_CMD, data: any = {}, statusCallback:StatusCallback): Promise<any> {
  log_message_library('Making lock');
  const res =  await send_command_locked(token, cmd, data, statusCallback);
  log_message_library('Releasing lock');
  return res
}

/**
 * All binary data have to be encoded into hex string. Returns hex strings.
 * @param token Session token
 * @param cmd Command to call
 * @param data All binary data have to be encoded into hex string. Returns hex strings.
 * @param statusCallback The callback for UI message logging
 */
async function _send_command(token: Session, cmd: WEBCRYPT_CMD, data: any = {}, statusCallback:StatusCallback): Promise<any> {
  if (cmd === WEBCRYPT_CMD.LOGOUT){
    token.clear();
  } else if (cmd !== WEBCRYPT_CMD.LOGIN) {
    data = token.authorize(data);
  }
  data = dict_binval(data);
  if (VERBOSE) log_message_library(`send_command, cmd:${cmd}, data:`, data);

  if (VERBOSE) log_message_library("final data sent", data);
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
    if (VERBOSE) log_message_library(`send_command finished, cmd:${cmd}`);
    return {};
  }
  const result = CBOR.decode(response_cbor.buffer);
  if (VERBOSE) log_message_library(`send_command finished, cmd:${cmd}, result:`, result);

  return dict_hexval(result);
}



// gather_platform_info();
