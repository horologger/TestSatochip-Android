package org.satochip.testsatochip.ui.components

import android.util.Log
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import org.satochip.testsatochip.R
import org.satochip.testsatochip.data.NfcResultCode
import kotlin.time.Duration.Companion.seconds

private const val TAG = "NfcDialog"


@Composable
fun NfcDialog(
    openDialogCustom: MutableState<Boolean>,
    resultCodeLive: NfcResultCode,
    isConnected: Boolean
) {
    BottomDrawer(
        showSheet = openDialogCustom
    ) {
        LaunchedEffect(resultCodeLive) {
            Log.d(TAG, "LaunchedEffect START ${resultCodeLive}")
            while (resultCodeLive == NfcResultCode.Busy || resultCodeLive == NfcResultCode.None) {
                Log.d(TAG, "LaunchedEffect in while delay 2s ${resultCodeLive}")
                delay(2.seconds)
            }
            Log.d(TAG, "LaunchedEffect after while delay ${resultCodeLive}")
        }
        if (resultCodeLive == NfcResultCode.Busy) {
            if (isConnected) {
                DrawerScreen(
                    closeSheet = {
                        openDialogCustom.value = !openDialogCustom.value
                    },
                    message = R.string.scanning,
                    image = R.drawable.phone_icon,
                    //message = NfcResultCode.Busy.res, // show?
                )
            } else {
                DrawerScreen(
                    closeSheet = {
                        openDialogCustom.value = !openDialogCustom.value
                    },
                    closeDrawerButton = true,
                    title = R.string.readyToScan,
                    image = R.drawable.phone_icon,
                    message = R.string.nfcHoldSeedkeeper
                )
            }
        } else {
            DrawerScreen(
                closeSheet = {
                    openDialogCustom.value = !openDialogCustom.value
                },
                title = resultCodeLive.resTitle,
                image = resultCodeLive.resImage,
                message = resultCodeLive.resMsg,
                colorFilter = if (resultCodeLive.resTitle == R.string.nfcTitleWarning) ColorFilter.tint(
                    Color.Yellow
                ) else null
            )
            LaunchedEffect(Unit) {
                delay(1.seconds)
                openDialogCustom.value = false
            }
        }
    }
}

@Composable
fun BottomDrawer(
    showSheet: MutableState<Boolean>,
    content: @Composable () -> Unit,
) {
    BottomSheet(showSheet = showSheet, modifier = Modifier) {
        Box(
            modifier = Modifier.padding(16.dp),
            contentAlignment = Alignment.Center
        ) {
            content()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BottomSheet(
    showSheet: MutableState<Boolean>,
    modifier: Modifier,
    content: @Composable () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(
        skipPartiallyExpanded = false
    )
    if (!showSheet.value) {
        return
    } else {
        ModalBottomSheet(
            modifier = modifier,
            containerColor = Color.White,
            sheetState = sheetState,
            onDismissRequest = {
                showSheet.value = !showSheet.value
            },
            shape = RoundedCornerShape(10.dp)
        ) {
            content()
        }
    }
}

@Composable
fun DrawerScreen(
    closeSheet: () -> Unit,
    closeDrawerButton: Boolean = false,
    title: Int? = null,
    message: Int? = null,
    image: Int? = null,
    colorFilter: ColorFilter? = null,
) {
    Column(
        modifier = Modifier
            .height(350.dp)
            .fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        title?.let {
            Text(
                text = stringResource(it),
                style = TextStyle(
                    color = Color.Black,
                    fontSize = 26.sp
                )
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
//        image?.let {
//            GifImage(
//                modifier = Modifier.size(125.dp),
//                image = image,
//                colorFilter = colorFilter
//            )
//
//            Spacer(modifier = Modifier.height(16.dp))
//        }

        message?.let {
            Text(
                text = stringResource(message),
                style = TextStyle(
                    color = Color.Black,
                    fontSize = 16.sp
                )
            )
        }
        Spacer(modifier = Modifier.height(16.dp))
//        if (closeDrawerButton) {
//            SatoButton(
//                modifier = Modifier.fillMaxWidth(),
//                onClick = closeSheet,
//                text = R.string.cancel,
//                buttonColor = SatoLightGrey,
//                textColor = Color.Black,
//                shape = RoundedCornerShape(20)
//            )
//        }
    }
}