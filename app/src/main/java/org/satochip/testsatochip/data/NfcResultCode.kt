package org.satochip.testsatochip.data

import org.satochip.testsatochip.R

enum class  NfcResultCode(val resTitle : Int, val resMsg : Int, val resImage : Int) {
    Ok(R.string.nfcTitleSuccess, R.string.nfcOk, R.drawable.icon_check_gif),
    UnknownError(R.string.nfcTitleWarning, R.string.nfcErrorOccured, R.drawable.error_24px),
    None(R.string.scanning, R.string.nfcResultCodeNone, R.drawable.error_24px),
    Busy(R.string.scanning, R.string.nfcResultCodeBusy, R.drawable.contactless_24px),
    NfcError(R.string.nfcTitleWarning, R.string.nfcResultCodeNfcError, R.drawable.error_24px),
}