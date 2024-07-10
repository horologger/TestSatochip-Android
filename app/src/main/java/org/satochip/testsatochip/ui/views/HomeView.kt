package org.satochip.testsatochip.ui.views

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import org.satochip.testsatochip.R
import org.satochip.testsatochip.ui.components.HomeHeaderRow
import org.satochip.testsatochip.ui.components.ScanButton

@Composable
fun HomeView(
    onClick: () -> Unit
) {

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.primary)
    ) {
        Image(
            painter = painterResource(R.drawable.seedkeeper_background),
            contentDescription = null,
            modifier = Modifier
                .fillMaxSize()
                .align(Alignment.BottomCenter),
            contentScale = ContentScale.FillBounds
        )
        Column(
            modifier = Modifier
                .fillMaxSize(),
            verticalArrangement = Arrangement.SpaceBetween,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            HomeHeaderRow(
                onClick = {},
            )
            ScanButton(
                text = R.string.scan
            ) {
                onClick()
            }
            Spacer(
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}