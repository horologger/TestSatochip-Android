package org.satochip.testsatochip.viewmodels

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch
import org.satochip.testsatochip.data.NfcResultCode
import org.satochip.testsatochip.data.TestItems
import org.satochip.testsatochip.services.CardState

private const val TAG = "TestSatochipViewModel"

class TestSatochipViewModel() : ViewModel() {

    @SuppressLint("StaticFieldLeak")
    private lateinit var context: Context

    var isCardConnected by mutableStateOf(false)
    var resultCodeLive by mutableStateOf(NfcResultCode.Busy)


    init {
        CardState.isConnected.observeForever {
            isCardConnected = it
        }
        CardState.resultCodeLive.observeForever {
            resultCodeLive = it
        }
    }

    fun setContext(context: Context) {
        this.context = context
        CardState.context = context
    }

    fun doTests(activity: Activity, testItem: TestItems) {
        CardState.actionType = testItem
        scanCardForAction(activity)
    }

    fun scanCardForAction(activity: Activity) {
        Log.d(TAG, "scanCardForAction START")
        viewModelScope.launch {
            CardState.scanCardForAction(activity)
        }
        Log.d(TAG, "scanCardForAction END")
    }

}