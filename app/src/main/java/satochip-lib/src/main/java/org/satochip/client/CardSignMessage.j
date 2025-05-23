package org.satochip.client;

import android.util.Log;
import org.bouncycastle.util.encoders.Hex;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.ByteBuffer;
import org.satochip.io.APDUResponse;
import org.satochip.client.Constants;
import org.satochip.client.SatochipParser;

public class CardSignMessage {
    private static final String TAG = "CardSignMessage";
    private final SatochipParser parser;
    private final CardChannel cardChannel;

    public CardSignMessage(CardChannel cardChannel) {
        this.cardChannel = cardChannel;
        this.parser = new SatochipParser();
    }

    /**
     * Signs a message with the device.
     * Message is prepended with a specific header as described in Bitcoin message signing.
     *
     * @param keynbr The key to use (0xFF for bip32 key)
     * @param pubkey The public key used for signing and key recovery
     * @param message The message to sign
     * @param hmac The 20-byte hmac code required if 2FA is enabled
     * @param altcoin For altcoin signing
     * @return Object array containing [response, sw1, sw2, compsig]
     *         where compsig is the signature in compact 65-byte format
     */
    public Object[] cardSignMessage(byte keynbr, byte[] pubkey, String message, byte[] hmac, String altcoin) {
        Log.d(TAG, "In cardSignMessage");
        
        byte[] messageBytes = message.getBytes();
        byte[] altcoinBytes = altcoin != null ? altcoin.getBytes() : null;
        
        // Process message in chunks
        int chunk = 128; // max APDU data=255 => chunk<=255-(4+2)
        int bufferOffset = 0;
        int bufferLeft = messageBytes.length;

        try {
            // CIPHER_INIT - no data processed
            byte cla = Constants.CLA;
            byte ins = Constants.INS_SIGN_MESSAGE;
            byte p1 = keynbr; // 0xff=>BIP32 otherwise STD
            byte p2 = Constants.OP_INIT;
            int lc = altcoinBytes != null ? (0x4 + 0x1 + altcoinBytes.length) : 0x4;
            
            byte[] apdu = new byte[5 + lc];
            apdu[0] = cla;
            apdu[1] = ins;
            apdu[2] = p1;
            apdu[3] = p2;
            apdu[4] = (byte) lc;
            
            // Add buffer length (4 bytes)
            for (int i = 0; i < 4; i++) {
                apdu[5 + i] = (byte) ((bufferLeft >> (8 * (3 - i))) & 0xff);
            }
            
            // Add altcoin if present
            if (altcoinBytes != null) {
                apdu[9] = (byte) altcoinBytes.length;
                System.arraycopy(altcoinBytes, 0, apdu, 10, altcoinBytes.length);
            }

            // Send APDU
            APDUResponse response = cardChannel.send(new APDUCommand(apdu));
            int sw1 = response.getSw1();
            int sw2 = response.getSw2();

            // CIPHER PROCESS/UPDATE (optional)
            while (bufferLeft > chunk) {
                p2 = Constants.OP_PROCESS;
                lc = 2 + chunk;
                apdu = new byte[5 + lc];
                apdu[0] = cla;
                apdu[1] = ins;
                apdu[2] = p1;
                apdu[3] = p2;
                apdu[4] = (byte) lc;
                apdu[5] = (byte) ((chunk >> 8) & 0xFF);
                apdu[6] = (byte) (chunk & 0xFF);
                System.arraycopy(messageBytes, bufferOffset, apdu, 7, chunk);
                
                response = cardChannel.send(new APDUCommand(apdu));
                sw1 = response.getSw1();
                sw2 = response.getSw2();
                
                bufferOffset += chunk;
                bufferLeft -= chunk;
            }

            // CIPHER FINAL/SIGN (last chunk)
            chunk = bufferLeft;
            p2 = Constants.OP_FINALIZE;
            lc = 2 + chunk + (hmac != null ? hmac.length : 0);
            apdu = new byte[5 + lc];
            apdu[0] = cla;
            apdu[1] = ins;
            apdu[2] = p1;
            apdu[3] = p2;
            apdu[4] = (byte) lc;
            apdu[5] = (byte) ((chunk >> 8) & 0xFF);
            apdu[6] = (byte) (chunk & 0xFF);
            System.arraycopy(messageBytes, bufferOffset, apdu, 7, chunk);
            if (hmac != null) {
                System.arraycopy(hmac, 0, apdu, 7 + chunk, hmac.length);
            }

            response = cardChannel.send(new APDUCommand(apdu));
            sw1 = response.getSw1();
            sw2 = response.getSw2();

            // Parse signature from response
            byte[] compsig = new byte[0];
            if (sw1 == 0x90 && sw2 == 0x00) {
                // Prepend the message for signing as done inside the card
                byte[] hash = sha256d(msgMagic(messageBytes, altcoinBytes));
                Log.d(TAG, "DEBUG: hash: " + Hex.toHexString(hash));
                compsig = parser.parseMessageSignature(response.getData(), hash, pubkey);
            } else {
                Log.w(TAG, "Unexpected error in cardSignMessage() (error code " + 
                    String.format("0x%04X", (sw1 << 8) | sw2) + ")");
            }

            return new Object[]{response, sw1, sw2, compsig};

        } catch (Exception e) {
            Log.e(TAG, "Error in cardSignMessage: " + e.getMessage());
            return new Object[]{null, (byte)0x6F, (byte)0x00, new byte[0]};
        }
    }

    /**
     * Prepares the message for signing by adding the Bitcoin message magic prefix.
     */
    private byte[] msgMagic(byte[] message, byte[] altcoin) {
        byte[] prefix = "Bitcoin Signed Message:\n".getBytes();
        byte[] length = varInt(message.length);
        byte[] result = new byte[prefix.length + length.length + message.length];
        
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(length, 0, result, prefix.length, length.length);
        System.arraycopy(message, 0, result, prefix.length + length.length, message.length);
        
        return result;
    }

    /**
     * Creates a variable-length integer for the message length.
     */
    private byte[] varInt(int i) {
        if (i < 0xfd) {
            return new byte[]{(byte)i};
        } else if (i <= 0xffff) {
            return new byte[]{(byte)0xfd, (byte)(i >> 8), (byte)i};
        } else if (i <= 0xffffffffL) {
            return new byte[]{(byte)0xfe, (byte)(i >> 24), (byte)(i >> 16), (byte)(i >> 8), (byte)i};
        } else {
            return new byte[]{(byte)0xff, (byte)(i >> 56), (byte)(i >> 48), (byte)(i >> 40), 
                            (byte)(i >> 32), (byte)(i >> 24), (byte)(i >> 16), (byte)(i >> 8), (byte)i};
        }
    }

    /**
     * Performs double SHA-256 hashing.
     */
    private byte[] sha256d(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash1 = digest.digest(input);
            return digest.digest(hash1);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "SHA-256 algorithm not found: " + e.getMessage());
            return new byte[0];
        }
    }
} 