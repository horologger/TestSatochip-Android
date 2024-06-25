package org.satochip.testsatochip.data

enum class NfcActionType {
    ScanCard,
    TakeOwnership,
    ReleaseOwnership,
    SealSlot,
    UnsealSlot,
    ResetSlot,
    GetPrivkey,
    DoNothing,
}