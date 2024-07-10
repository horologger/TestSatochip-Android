package org.satochip.testsatochip.data

enum class TestItems(val value: String) {
    GoBack(""),
    ScanCard(""),
    DoNothing(""),
    SeedKeeperMemory("Seedkeeper memory"),
    GenerateMasterSeed("Generate masterseed"),
    GenerateRandomSecret("Generate random secret"),
    ImportExportSecretPlain("Import export secret plain"),
    ImportExportSecretEncrypted("Import export secret encripted"),
    Bip39MnemonicV2("Bip39 mnemonic v2"),
    CardBip32GetExtendedKeySeedVector1("Card Bip32 get extended key seed vector1"),
    CardBip32GetExtendedKeySeedVector2("Card Bip32 get extended key seed vector2"),
    CardBip32GetExtendedKeySeedVector3("Card Bip32 get extended key seed vector3"),
    CardBip32GetExtendedKeyBip85("Card bip32 get extended key bip85"),
    ResetSecrets("Reset secrets"),
}