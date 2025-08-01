package org.satochip.testsatochip.data

enum class TestItems(val value: String) {
    GoBack(""),
    ScanCard(""),
    DoNothing(""),
    SeedKeeperMemory("Seedkeeper memory"),
    GenerateMasterSeed("Generate masterseed"),
    GenerateRandomSecret("Generate random secret"),
    ImportExportSecretPlain("Import export secret plain"),
    ImportExportSecretEncrypted("Import export secret encrypted"),
    Bip39MnemonicV2("Bip39 mnemonic v2"),
    CardBip32GetExtendedKeySeedVector1("Pubkey Keyslot 1"),
    CardBip32GetExtendedKeySeedVector2("Bip32 get extended key seed vector2"),
    CardBip32GetExtendedKeySeedVector3("Bip32 get extended key seed vector3"),
    CardBip32GetExtendedKeyBip85("bip32 get extended key bip85"),
    ResetSecrets("Reset secrets"),
    CheckAuthenticity("Check authenticity"),
    SignMessage("Sign Transaction Hash"),
    SignSchnorrHash("Sign Schnorr Hash"),
    SignNostrEvent("Sign Nostr Event")
}