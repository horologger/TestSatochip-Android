package org.satochip.testsatochip.ui.views

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.satochip.testsatochip.R
import org.satochip.testsatochip.services.SatoLog
import org.satochip.testsatochip.ui.components.HeaderRow
import java.util.logging.Level

@Composable
fun ShowLogsView(
    onClick: () -> Unit,
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
                .fillMaxSize()
                .padding(top = 20.dp),
            verticalArrangement = Arrangement.SpaceBetween,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            HeaderRow(
                onClick = {
                    onClick()
                    SatoLog.emptyList()
                },
                titleText = R.string.testsTitle,
            )
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp)
            ) {
                items(SatoLog.logList) { log ->
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(
                                color = Color.White.copy(alpha = 0.2f)
                            )
                            .padding(horizontal = 16.dp)
                    ) {
                        Text(
                            modifier = Modifier.padding(top = 10.dp, bottom = 5.dp),
                            textAlign = TextAlign.Start,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Medium,
                            color = Color.Black,
                            text = log.date.toString()
                        )
                        Text(
                            modifier = Modifier.padding(top = 5.dp, bottom = 5.dp),
                            textAlign = TextAlign.Start,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Medium,
                            color = Color.Black,
                            text = "${getEmojiFromLevel(log.level)} ${log.level.name} - ${log.tag}"
                        )
                        Text(
                            modifier = Modifier.padding(top = 5.dp, bottom = 10.dp),
                            textAlign = TextAlign.Start,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Medium,
                            color = Color.Black,
                            text = log.msg
                        )
                    }
                    Divider(color = Color.LightGray)
                }
            }
        }
    }
}

private fun getEmojiFromLevel(level: Level): String {
    return when (level) {
        Level.SEVERE -> "\uD83D\uDD34"
        Level.WARNING -> "\uD83D\uDFE1"
        Level.INFO -> "\uD83D\uDD35"
        Level.CONFIG -> "\uD83D\uDFE2"
        else -> "\uD83D\uDD34" // should not happen
    }
}