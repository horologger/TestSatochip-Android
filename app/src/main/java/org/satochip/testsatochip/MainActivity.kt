package org.satochip.testsatochip

import android.app.Activity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import org.satochip.testsatochip.ui.components.NfcDialog
import org.satochip.testsatochip.ui.theme.TestSatochipTheme
import org.satochip.testsatochip.ui.views.HomeView
import org.satochip.testsatochip.viewmodels.TestSatochipViewModel

class MainActivity : ComponentActivity() {

    private val viewModel: TestSatochipViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            TestSatochipTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val context = LocalContext.current
                    viewModel.setContext(context)
                    val showNfcDialog = remember { mutableStateOf(false) } // for NfcDialog
                    // NfcDialog
                    if (showNfcDialog.value) {
                        NfcDialog(
                            openDialogCustom = showNfcDialog,
                            resultCodeLive = viewModel.resultCodeLive,
                            isConnected = viewModel.isCardConnected
                        )
                    }
                    HomeView (
                        onClick = {
                            showNfcDialog.value = !showNfcDialog.value
                            viewModel.scanCard(context as Activity)
                        }
                    )
                }
            }
        }
    }
}