package org.satochip.testsatochip.services

import android.util.Log
import org.satochip.client.SatochipCommandSet
import org.satochip.io.CardChannel
import org.satochip.io.CardListener
import org.satochip.testsatochip.data.NfcResultCode

private const val TAG = "SatochipCardListener"

object SatochipCardListenerForAction : CardListener {

    override fun onConnected(cardChannel: CardChannel?) {

        CardState.isConnected.postValue(true)
        SatoLog.d(TAG, "onConnected: Card is connected")
        try {
            val cmdSet = SatochipCommandSet(cardChannel)
            // start to interact with card
            CardState.initialize(cmdSet)

            // TODO: disconnect?
            onDisconnected()
            // disable scanning once finished
            Thread.sleep(100) // delay to let resultCodeLive update (avoid race condition?)
            SatoLog.d(TAG, "onConnected: resultAfterConnection delay: ${CardState.resultCodeLive.value}")
            if (CardState.resultCodeLive.value != NfcResultCode.UnknownError) { //todo: refine condition?
                // if result is OK, or failed with a known reason, we stop polling for the card
                CardState.disableScanForAction()
            }

        } catch (e: Exception) {
            SatoLog.e(TAG, "onConnected: an exception has been thrown during card init.")
            SatoLog.e(TAG, Log.getStackTraceString(e))
            onDisconnected()
        }
    }

    override fun onDisconnected() {
        CardState.isConnected.postValue(false)
        CardState.resultCodeLive.postValue(NfcResultCode.Ok)

        SatoLog.d(TAG, "onDisconnected: Card disconnected!")
    }
}