import { Crypto } from "@peculiar/webcrypto";
import { Convert } from "pvtsutils";
import * as DKeyRatchet from "2key-ratchet";

const main = async () => {
    // Using implementation of WebCrypto browser API for NodeJS.
    const crypto = new Crypto();
    DKeyRatchet.setEngine("@peculiar/webcrypto", crypto);

    // Create ID and Key Bundle to be filled.
    const AliceID = await DKeyRatchet.Identity.create(16453, 1);
    const AlicePreKeyBundle = new DKeyRatchet.PreKeyBundleProtocol();
    await AlicePreKeyBundle.identity.fill(AliceID);

    AlicePreKeyBundle.registrationId = AliceID.id;
    // Info about signed PreKey
    const preKey = AliceID.signedPreKeys[0];
    AlicePreKeyBundle.preKeySigned.id = 0;
    AlicePreKeyBundle.preKeySigned.key = preKey.publicKey;
    await AlicePreKeyBundle.preKeySigned.sign(AliceID.signingKey.privateKey);

    // Proto => Bytes to be sent to Bob.
    const AlicePreKeyBundleProto = await AlicePreKeyBundle.exportProto();
    console.log("Alice's bundle: ", Convert.ToHex(AlicePreKeyBundleProto));

    const BobID = await DKeyRatchet.Identity.create(0, 1);
    // Parse Alice's bundle
    const bundle = await DKeyRatchet.PreKeyBundleProtocol.importProto(AlicePreKeyBundleProto);
    // Create Bob's cipher
    const BobCipher = await DKeyRatchet.AsymmetricRatchet.create(BobID, bundle);
    // Encrypt message for Alice
    const BobMessageProto = await BobCipher.encrypt(Convert.FromUtf8String("Hello Alice!!!"));
    // Proto => Bytes for Alice
    const BobMessage = await BobMessageProto.exportProto();
    console.log("Bob's encrypted message:", Convert.ToHex(BobMessage));

    // parse Bob's message (Bytes => Proto)
    const proto = await DKeyRatchet.PreKeyMessageProtocol.importProto(BobMessage);
    // Create Alice's cipher for Bob's message
    const AliceCipher = await DKeyRatchet.AsymmetricRatchet.create(AliceID, proto);

    const bytes = await AliceCipher.decrypt(proto.signedMessage);
    console.log("Bob's decrypted message (by Alice):", Convert.ToUtf8String(bytes));
}

main().catch((e) => console.error(e))