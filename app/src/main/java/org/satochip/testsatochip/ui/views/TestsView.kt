package org.satochip.testsatochip.ui.views

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.satochip.testsatochip.R
import org.satochip.testsatochip.data.TestItems
import org.satochip.testsatochip.ui.components.HeaderRow
import org.satochip.testsatochip.ui.components.HomeHeaderRow
import android.util.Log

@Composable
fun TestsView(
    onClick: (TestItems) -> Unit
) {
    val testItems = TestItems.entries.filter { it.value.isNotEmpty() }
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
                .padding(top = 10.dp),
            verticalArrangement = Arrangement.Top,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            HomeHeaderRow(
                onClick = {},
                titleText = R.string.testsTitle
            )
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(top = 20.dp)
            ) {
                LazyColumn(
                    modifier = Modifier.weight(1f)
                ) {
                    items(testItems) { item ->
                        // Special handling for Sign Transaction Hash and Sign Schnorr Hash buttons
                        if (item == TestItems.SignMessage || item == TestItems.SignSchnorrHash) {
                            Button(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 8.dp, vertical = 4.dp),
                                onClick = {
                                    onClick(item)
                                },
                            ) {
                                Text(
                                    text = item.value,
                                    style = TextStyle(
                                        color = Color.White
                                    ),
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        } else {
                            // Regular 2-column layout for other buttons
                            val remainingItems = testItems.filter { it != TestItems.SignMessage && it != TestItems.SignSchnorrHash }
                            val itemIndex = remainingItems.indexOf(item)
                            if (itemIndex % 2 == 0) {
                                val nextItem = if (itemIndex + 1 < remainingItems.size) remainingItems[itemIndex + 1] else null
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(8.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Button(
                                        modifier = Modifier
                                            .weight(1f)
                                            .padding(4.dp),
                                        onClick = {
                                            onClick(item)
                                        },
                                    ) {
                                        Text(
                                            text = item.value,
                                            style = TextStyle(
                                                color = Color.White
                                            ),
                                            maxLines = 2,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                    if (nextItem != null) {
                                        Button(
                                            modifier = Modifier
                                                .weight(1f)
                                                .padding(4.dp),
                                            onClick = {
                                                onClick(nextItem)
                                            },
                                        ) {
                                            Text(
                                                text = nextItem.value,
                                                style = TextStyle(
                                                    color = Color.White
                                                ),
                                                maxLines = 2,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                        }
                                    } else {
                                        // Empty space to maintain layout
                                        androidx.compose.foundation.layout.Spacer(modifier = Modifier.weight(1f))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}