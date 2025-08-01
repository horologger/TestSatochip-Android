## Examples

### Complete Satochip Transaction Signing

```java
public class SatochipSigner implements CardListener {
    private String pin = "123456";
    private String derivationPath = "m/44'/0'/0'/0/0";
    private byte[] transactionHash;
    
    @Override
    public void onConnected(CardChannel channel) {
        SatochipCommandSet commandSet = new SatochipCommandSet(channel);
        
        try {
            // Select Satochip applet
            commandSet.cardSelect("satochip").checkOK();
            
            // Verify PIN
            commandSet.cardVerifyPIN(pin.getBytes(StandardCharsets.UTF_8));
            
            // Get extended key for signing
            byte[][] extendedKey = commandSet.cardBip32GetExtendedKey(derivationPath);
            byte[] publicKey = extendedKey[0];
            
            // Sign transaction hash
            APDUResponse signResponse = commandSet.cardSignTransactionHash(
                (byte)0xFF, 
                transactionHash, 
                null
            );
            
            byte[] signature = signResponse.getData();
            
            // Process signature...
            onSigningComplete(signature, publicKey);
            
        } catch (Exception e) {
            onSigningError(e);
        }
    }
    
    private void onSigningComplete(byte[] signature, byte[] publicKey) {
        // Handle successful signing
    }
    
    private void onSigningError(Exception error) {
        // Handle errors
    }
    
    @Override
    public void onDisconnected() {
        // Handle disconnection
    }
}
```

### Satodime Key Management

```java
public void manageSatodimeKey(SatochipCommandSet commandSet, int keySlot) {
    try {
        // Get key slot status
        APDUResponse statusResponse = commandSet.satodimeGetKeyslotStatus(keySlot);
        SatodimeKeyslotStatus keyStatus = new SatodimeKeyslotStatus(statusResponse);
        
        byte state = keyStatus.getKeyStatus();
        
        switch (state) {
            case Constants.STATE_UNINITIALIZED:
                // Set up the key slot
                byte[] slip44 = new byte[]{0x00, 0x00, 0x00, 0x00}; // Bitcoin
                byte[] contract = new byte[34]; // Empty contract
                byte[] tokenId = new byte[34]; // Empty token ID
                
                commandSet.satodimeSetKeyslotStatusPart0(
                    keySlot, 0, 0, 0x01, slip44, contract, tokenId
                );
                
                // Seal the key with entropy
                byte[] entropy = new byte[32];
                new SecureRandom().nextBytes(entropy);
                commandSet.satodimeSealKey(keySlot, entropy);
                break;
                
            case Constants.STATE_SEALED:
                // Get public key (doesn't change state)
                APDUResponse pubkeyResponse = commandSet.satodimeGetPubkey(keySlot);
                byte[] publicKey = pubkeyResponse.getData();
                
                // To get private key, unseal first
                commandSet.satodimeUnsealKey(keySlot);
                APDUResponse privkeyResponse = commandSet.satodimeGetPrivkey(keySlot);
                break;
                
            case Constants.STATE_UNSEALED:
                // Already unsealed, can get private key
                APDUResponse privkeyResponse2 = commandSet.satodimeGetPrivkey(keySlot);
                break;
        }
        
    } catch (Exception e) {
        // Handle errors
    }
}
```

### Seedkeeper Backup and Restore

```java
public void backupAndRestore(SatochipCommandSet commandSet) {
    try {
        // Generate a master seed
        SeedkeeperSecretHeader seedHeader = commandSet.seedkeeperGenerateMasterseed(
            32,
            SeedkeeperExportRights.EXPORT_PLAINTEXT_ALLOWED,
            "Master Seed Backup"
        );
        
        int seedId = seedHeader.sid;
        
        // List all secrets
        List<SeedkeeperSecretHeader> headers = commandSet.seedkeeperListSecretHeaders();
        for (SeedkeeperSecretHeader header : headers) {
            System.out.println("Found secret: " + header.label + " (ID: " + header.sid + ")");
        }
        
        // Export the seed
        SeedkeeperSecretObject exportedSeed = commandSet.seedkeeperExportSecret(seedId, null);
        byte[] seedData = exportedSeed.getSecretBytes();
        
        // Save seedData securely...
        
        // Later, import it back (on another card or after reset)
        SeedkeeperSecretObject importObject = new SeedkeeperSecretObject(
            seedData,
            new SeedkeeperSecretHeader(
                0, // Will be assigned new ID
                SeedkeeperSecretType.MASTERSEED,
                (byte)0,
                SeedkeeperSecretOrigin.PLAIN_IMPORT,
                SeedkeeperExportRights.EXPORT_PLAINTEXT_ALLOWED,
                (byte)0, (byte)0, (byte)0,
                SeedkeeperSecretHeader.getFingerprintBytes(seedData),
                "Restored Master Seed"
            )
        );
        
        SeedkeeperSecretHeader restoredHeader = commandSet.seedkeeperImportSecret(importObject);
        
    } catch (Exception e) {
        // Handle errors
    }
}
```

### Nostr Event Signing

```java
public void signNostrEvent(SatochipCommandSet commandSet) {
    try {
        // Set PIN environment variable (in production, use secure input)
        System.setProperty("PYSATOCHIP_PIN", "123456");
        
        // Sign a Nostr text note
        String signedEvent = commandSet.satochipSignNostrEvent(
            0xFF,                           // Use extended key derivation
            "m/44'/0'/0'/0/0",             // BIP32 path for Bitcoin
            "Hello from Satochip! 🚀",      // Message content
            1,                              // Kind 1 (text note)
            true,                           // Broadcast to relay
            "wss://relay.damus.io"          // Relay URL
        );
        
        System.out.println("Signed Nostr event:");
        System.out.println(signedEvent);
        
        // Parse the JSON to extract components
        // The returned string is a valid Nostr event JSON
        // You can parse it with any JSON library
        
    } catch (Exception e) {
        System.err.println("Error signing Nostr event: " + e.getMessage());
        e.printStackTrace();
    }
}

public void signNostrEventWithCustomPath(SatochipCommandSet commandSet) {
    try {
        // Sign using a specific BIP32 path
        String signedEvent = commandSet.satochipSignNostrEvent(
            0xFF,                           // Use extended key derivation
            "m/44'/0'/0'/0/1",             // Different derivation path
            "Custom path message",          // Message content
            1,                              // Kind 1 (text note)
            false,                          // Don't broadcast (just sign)
            null                            // No relay needed
        );
        
        System.out.println("Event signed successfully (not broadcast):");
        System.out.println(signedEvent);
        
    } catch (Exception e) {
        System.err.println("Error: " + e.getMessage());
    }
}
```
```
