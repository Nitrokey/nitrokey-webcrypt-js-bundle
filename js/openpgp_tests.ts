import {
    createCleartextMessage,
    createMessage,
    decrypt,
    encrypt,
    generateKey,
    readCleartextMessage,
    readMessage,
    readSignature,
    sign,
    verify
} from "openpgp/lightweight";
import {StatusCallback} from "./types";
import {
    WEBCRYPT_OPENPGP_DECRYPT,
    WEBCRYPT_OPENPGP_GENERATE,
    WEBCRYPT_OPENPGP_IMPORT,
    WEBCRYPT_OPENPGP_INFO,
    WEBCRYPT_OPENPGP_SIGN
} from "./webcrypt";
import {equalBuffer, hexStringToByte} from "./helpers";


export async function openpgpTests_ext(statusCallback: StatusCallback): Promise<void> {
    const {encr_pubkey, sign_pubkey, date: webcrypt_date} = await WEBCRYPT_OPENPGP_INFO(statusCallback);

    console.log('webcrypt openpgp info',
        {encr_pubkey, sign_pubkey, date: webcrypt_date}
    );

    const plugin = {
        type: 'none',
        date: webcrypt_date ? new Date(webcrypt_date) : new Date(2019, 1, 1), // the default WebCrypt date for the created keys
        public_sign: sign_pubkey,
        public_encr: encr_pubkey,

        agree: async function (curve: any, V: any, Q: any, d: any): Promise<{ secretKey: Uint8Array, sharedKey: Uint8Array }> {
            console.log({curve, V, Q, d});
            // @returns {Promise<{secretKey: Uint8Array, sharedKey: Uint8Array}>}
            const agreed_secret = await WEBCRYPT_OPENPGP_DECRYPT(statusCallback, V);
            return {secretKey: d, sharedKey: agreed_secret};
        },
        decrypt: async function (oid: any, kdfParams: any, V: any, Cdata: any, Q: any, d: any, fingerprint: any) {
            // unused
            // @returns {Promise<Uint8Array>} Decrypted data.
            console.log({oid, kdfParams, V, Cdata, Q, d, fingerprint, name: 'decrypt plugin'});
        },
        sign: async function (oid: any, hashAlgo: any, data: any, Q: any, d: any, hashed: any) {
            console.log("sign", {oid, hashAlgo, data, Q, d, hashed, plugin: this, name: "sign"});
            // TODO investigate, why data/message is used for signing and verification, and not the hash
            // TODO ...., why signatures during key generation and use are not verified
            // const res = await WEBCRYPT_OPENPGP_SIGN(statusCallback, hashed);
            const res = await WEBCRYPT_OPENPGP_SIGN(statusCallback, data);
            const resb = hexStringToByte(res);
            const r = resb.slice(0, 32);
            const s = resb.slice(32, 64);
            const reso = {r, s};
            console.log("sign results", {
                resb,
                reso,
                oid,
                hashAlgo,
                data,
                Q,
                d,
                hashed,
                plugin: this,
                name: "sign res"
            });
            console.log(`Using key for signing: ${Q}`)
            return reso;
        },
        generateKeyPair: async function (keyType: any) {
            console.log({keyType, name: "genkey", plugin: this});
            let selected_pk = this.public_sign;
            if (this.type === 'sub') {
                selected_pk = this.public_encr;
                console.log(`Selecting subkey: ${selected_pk} for encryption`);
            } else {
                console.log(`Selecting main: ${selected_pk} for signing`);
            }
            return {publicKey: selected_pk, privateKey: new Uint8Array(32).fill(42)};
        }
    };

    console.log("test software key generation");
    const {privateKey, publicKey} = await generateKey({
        curve: 'p256',
        userIDs: [{name: 'Jon Smith', email: 'jon@example.com'}],
        format: 'object',
    });
    console.log('k1');
    console.log({privateKey, publicKey});

    console.log("test plugin based key generation");
    const {privateKey: webcrypt_privateKey, publicKey: webcrypt_publicKey} = await generateKey({
        // @ts-ignore
        curve: 'webcrypt_p256',
        userIDs: [{name: 'Jon Smith', email: 'jon@example.com'}],
        format: 'object',
        date: plugin.date,
        plugin: plugin,
    });
    console.log('k2');
    console.log({webcrypt_privateKey, webcrypt_publicKey});

    {
        const {privateKey: webcrypt_privateKey2, publicKey: webcrypt_publicKey2} = await generateKey({
            // @ts-ignore
            curve: 'webcrypt_p256',
            userIDs: [{name: 'Jon Smith', email: 'jon@example.com'}],
            format: 'armored',
            date: plugin.date,
            plugin: plugin,
        });
        console.log('webcrypt keys armored', {webcrypt_privateKey2, webcrypt_publicKey2});
    }

    //////////////////////////////

    {
        console.log("Encrypting message software");
        console.log({privateKey, publicKey});
        const encrypted2 = await encrypt({
            message: await createMessage({text: 'Hello, World!'}),
            encryptionKeys: publicKey,
            format: 'binary'
        });
        console.log({encrypted2});
        const message = await readMessage({
            binaryMessage: encrypted2
        });
        console.log("after read message");

        const {data: decrypted, signatures} = await decrypt({
            message,
            decryptionKeys: privateKey
        });
        console.log({decrypted}); // 'Hello, World!'
    }

    {
        console.log("Encrypting message webcrypt");
        const encrypted = await encrypt({
            message: await createMessage({text: 'Hello, World!'}),
            encryptionKeys: webcrypt_publicKey,
            format: 'binary'
        });
        console.log({encrypted});
        console.log("before read binary message");

        const message = await readMessage({
            binaryMessage: encrypted
        });
        console.log("after read message");

        const {data: decrypted, signatures} = await decrypt({
            message,
            decryptionKeys: webcrypt_privateKey,
            // @ts-ignore
            plugin: plugin,
        });
        console.log({decrypted}); // 'Hello, World!'
    }

    {
        console.log("Signing message software");

        const message = await createMessage({text: 'Hello, World!'});
        const detachedSignature = await sign({
            message, // Message object
            signingKeys: privateKey,
            detached: true
        });
        console.log(detachedSignature);

        const signature = await readSignature({
            armoredSignature: detachedSignature // parse detached signature
        });
        const verificationResult = await verify({
            message, // Message object
            signature,
            verificationKeys: publicKey
        });
        const {verified, keyID} = verificationResult.signatures[0];
        try {
            await verified; // throws on invalid signature
            console.log('Signed by key id ' + keyID.toHex());
        } catch (e: any) {
            throw new Error('Signature could not be verified: ' + e.message);
        }
    }

    {
        console.log("Signing message webcrypt detached");
        console.log({privateKey, webcrypt_privateKey});

        const message = await createMessage({text: 'Hello, World!'});
        const detachedSignature = await sign({
            message, // Message object
            signingKeys: webcrypt_privateKey,
            // @ts-ignore
            plugin: plugin,
            detached: true
        });
        console.log({detachedSignature});

        const signature = await readSignature({
            armoredSignature: detachedSignature // parse detached signature
        });

        // console.log({ armoredPublicKey: armor(webcrypt_publicKey) });

        const verificationResult = await verify({
            message, // Message object
            signature,
            verificationKeys: webcrypt_publicKey
        });

        console.log('Before verification');
        const {verified, keyID} = verificationResult.signatures[0];
        try {
            await verified; // throws on invalid signature
            console.log('webcrypt detached Signed by key id ' + keyID.toHex());
        } catch (e: any) {
            throw new Error('webcrypt detached Signature could not be verified: ' + e.message);
        }
    }

    {
        console.log("Signing message software non-detached");

        const unsignedMessage = await createCleartextMessage({text: 'Hello, World!'});
        const cleartextMessage = await sign({
            message: unsignedMessage, // CleartextMessage or Message object
            signingKeys: privateKey
        });
        console.log(cleartextMessage); // '-----BEGIN PGP SIGNED MESSAGE ... END PGP SIGNATURE-----'

        const signedMessage = await readCleartextMessage({
            cleartextMessage // parse armored message
        });
        const verificationResult = await verify({
            // @ts-ignore
            message: signedMessage,
            verificationKeys: publicKey
        });
        const {verified, keyID} = verificationResult.signatures[0];
        try {
            await verified; // throws on invalid signature
            console.log('Signed by key id ' + keyID.toHex());
        } catch (e: any) {
            throw new Error('Signature could not be verified: ' + e.message);
        }
    }


    {
        console.log("Signing message webcrypt non-detached");

        const unsignedMessage = await createCleartextMessage({text: 'Hello, World!'});
        console.log('before signing');
        const cleartextMessage = await sign({
            message: unsignedMessage, // CleartextMessage or Message object
            signingKeys: webcrypt_privateKey,
            plugin: plugin
        });
        console.log('after signing', {cleartextMessage}); // '-----BEGIN PGP SIGNED MESSAGE ... END PGP SIGNATURE-----'

        const signedMessage = await readCleartextMessage({
            cleartextMessage // parse armored message
        });
        console.log('before verification');
        const verificationResult = await verify({
            // @ts-ignore
            message: signedMessage,
            verificationKeys: webcrypt_publicKey
        });
        const {verified, keyID} = verificationResult.signatures[0];
        try {
            await verified; // throws on invalid signature
            console.log('Webcrypt: Signed by key id ' + keyID.toHex());
        } catch (e: any) {
            throw new Error('Signature could not be verified: ' + e.message);
        }
    }
    console.log(`Webcrypt public fingerprint: ${webcrypt_publicKey.getFingerprint()}`);

    {
        console.log("Signing big message webcrypt non-detached");

        const unsignedMessage = await createCleartextMessage({text: 'Hello, World!'.padEnd(980, '=')}); // 980, 900, 500 works, 1100 does not
        console.log('before signing');
        const cleartextMessage = await sign({
            message: unsignedMessage,
            signingKeys: webcrypt_privateKey,
            plugin: plugin
        });
        console.log('after signing', {cleartextMessage}); // '-----BEGIN PGP SIGNED MESSAGE ... END PGP SIGNATURE-----'

        const signedMessage = await readCleartextMessage({
            cleartextMessage // parse armored message
        });
        console.log('before verification');
        const verificationResult = await verify({
            // @ts-ignore
            message: signedMessage,
            verificationKeys: webcrypt_publicKey
        });
        const {verified, keyID} = verificationResult.signatures[0];
        try {
            await verified; // throws on invalid signature
            console.log('Webcrypt: big Signed by key id ' + keyID.toHex());
        } catch (e: any) {
            throw new Error('Signature could not be verified: ' + e.message);
        }
    }

    {
        console.log("Import openpgp generated key by abusing plugin and signing message");
        console.log('Current webcrypt keys and the software generated public key (before)', {
            privateKey,
            WebcryptKeys: await WEBCRYPT_OPENPGP_INFO(statusCallback),
        });

        // alternative import solution by abusing the sign operation in the plugin
        // const unsignedMessage = await createCleartextMessage({ text: 'Hello, World!' });
        // const cleartextMessage = await sign({
        //     message: unsignedMessage,
        //     signingKeys: privateKey,
        //     plugin: {
        //         sign: async function (oid:any, hashAlgo:any, data:any, Q:any, d:any, hashed:any) {
        //             console.log('in importing plugin call');
        //             // await WEBCRYPT_OPENPGP_IMPORT(statusCallback, {sign_privkey: d});
        //             return {r: new Uint8Array(32).fill(42), s: new Uint8Array(32).fill(43) };
        //         },
        //     }
        // });
        // console.log(cleartextMessage);

        // import solution by using the private API directly (not exposed in the Typescript definitions)
        await WEBCRYPT_OPENPGP_IMPORT(statusCallback, {
            // @ts-ignore
            sign_privkey: privateKey.keyPacket.privateParams.d,
            // @ts-ignore
            encr_privkey: privateKey.subkeys[0].keyPacket.privateParams.d,
            date: privateKey.getCreationTime(),
        });

        const webcrypt_openpgp_keys_current = await WEBCRYPT_OPENPGP_INFO(statusCallback);
        console.log('Current webcrypt keys and the software generated public key (after)', {
            privateKey,
            WebcryptKeys: webcrypt_openpgp_keys_current,
        });
        console.log('Direct comparison of public keys', {
            // @ts-ignore
            // sign: equalBuffer(privateKey.keyPacket.publicParams.Q, webcrypt_openpgp_keys_current.sign_pubkey),
            sign: equalBuffer(publicKey.keyPacket.publicParams.Q, webcrypt_openpgp_keys_current.sign_pubkey),
            // @ts-ignore
            encr: equalBuffer(publicKey.subkeys[0].keyPacket.publicParams.Q, webcrypt_openpgp_keys_current.encr_pubkey),
        });

        const {
            privateKey: webcrypt_privateKey_after_import,
            publicKey: webcrypt_publicKey_after_import
        } = await generateKey({
            // @ts-ignore
            curve: 'webcrypt_p256',
            userIDs: [{name: 'Jon Smith', email: 'jon@example.com'}],
            format: 'object',
            // date: new Date(webcrypt_openpgp_keys_current.date),
            date: privateKey.getCreationTime(),
            plugin: plugin,
        });
        console.log({webcrypt_privateKey_after_import, webcrypt_publicKey_after_import});

        console.log('After-import fingerprint check', {
            sw: publicKey.getFingerprint(),
            wc: webcrypt_publicKey_after_import.getFingerprint(),
            eq: publicKey.getFingerprint() === webcrypt_publicKey_after_import.getFingerprint(),
            swd: publicKey.getCreationTime().getTime(),
            wcd: webcrypt_publicKey_after_import.getCreationTime().getTime()
        });
    }
    {
        const webcrypt_openpgp_keys_before = await WEBCRYPT_OPENPGP_INFO(statusCallback);
        await WEBCRYPT_OPENPGP_GENERATE(statusCallback);
        const webcrypt_openpgp_keys_current = await WEBCRYPT_OPENPGP_INFO(statusCallback);
        console.log('Current webcrypt keys and the regenerated key after WEBCRYPT_OPENPGP_GENERATE()', {
            webcrypt_openpgp_keys_before,
            webcrypt_openpgp_keys_current,
        });
    }

}

// console.log("new run --------------------", new Date().toLocaleTimeString());
// @ts-ignore
// openpgpTests_ext(console.log);
