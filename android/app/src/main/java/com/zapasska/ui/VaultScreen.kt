package com.zapasska.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zapasska.data.Entry

/** The list of entries, the search box and the row actions. */
@Composable
fun VaultScreen(
    entries: List<Entry>,
    query: String,
    onQueryChange: (String) -> Unit,
    revealed: String?,
    syncStatus: String,
    onToggleReveal: (String) -> Unit,
    onCopy: (Entry) -> Unit,
    onEdit: (Entry) -> Unit,
    onDelete: (Entry) -> Unit,
    onAdd: () -> Unit,
    onSync: () -> Unit,
    onLock: () -> Unit,
) {
    Box(Modifier.fillMaxSize().background(Palette.Background)) {
        Column(Modifier.fillMaxSize().padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text("Хранилище", fontSize = 20.sp, fontWeight = FontWeight.Bold,
                     color = Palette.Text)
                Row {
                    TextButton(onClick = onSync) { Text("☁", fontSize = 18.sp) }
                    TextButton(onClick = onLock) { Text("Выйти", color = Palette.TextDim) }
                }
            }

            OutlinedTextField(
                value = query,
                onValueChange = onQueryChange,
                label = { Text("Поиск") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            Text(syncStatus, color = Palette.TextDim, fontSize = 12.sp)
            Spacer(Modifier.height(8.dp))

            if (entries.isEmpty()) {
                Text("Пока пусто. Добавьте первую запись кнопкой внизу.",
                     color = Palette.TextDim, fontSize = 14.sp)
            }

            LazyColumn(Modifier.fillMaxSize()) {
                items(entries, key = { it.uuid }) { entry ->
                    EntryCard(
                        entry = entry,
                        revealed = entry.uuid == revealed,
                        onToggleReveal = { onToggleReveal(entry.uuid) },
                        onCopy = { onCopy(entry) },
                        onEdit = { onEdit(entry) },
                        onDelete = { onDelete(entry) },
                    )
                    Spacer(Modifier.height(8.dp))
                }
            }
        }

        FloatingActionButton(
            onClick = onAdd,
            modifier = Modifier.align(Alignment.BottomEnd).padding(20.dp),
        ) {
            Text("+", fontSize = 26.sp)
        }
    }
}

@Composable
private fun EntryCard(
    entry: Entry,
    revealed: Boolean,
    onToggleReveal: () -> Unit,
    onCopy: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp)) {
            Text(entry.service, color = Palette.Text, fontSize = 16.sp,
                 fontWeight = FontWeight.SemiBold)
            Text(entry.login, color = Palette.TextDim, fontSize = 13.sp)
            Spacer(Modifier.height(6.dp))
            Text(if (revealed) entry.password else "••••••••••••",
                 color = if (revealed) Palette.Accent else Palette.TextDim, fontSize = 14.sp)
            Spacer(Modifier.height(6.dp))
            Row {
                TextButton(onClick = onToggleReveal) {
                    Text(if (revealed) "Скрыть" else "Показать")
                }
                TextButton(onClick = onCopy) { Text("Копировать") }
                TextButton(onClick = onEdit) { Text("Изменить") }
                TextButton(onClick = onDelete) { Text("Удалить", color = Palette.Danger) }
            }
        }
    }
}

/** Add or edit one entry. */
@Composable
fun EntryDialog(
    title: String,
    service: String,
    login: String,
    password: String,
    onServiceChange: (String) -> Unit,
    onLoginChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onGenerate: () -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                OutlinedTextField(service, onServiceChange, singleLine = true,
                                  label = { Text("Сервис") },
                                  modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(login, onLoginChange, singleLine = true,
                                  label = { Text("Логин") },
                                  modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(password, onPasswordChange, singleLine = true,
                                  label = { Text("Пароль") },
                                  modifier = Modifier.fillMaxWidth())
                TextButton(onClick = onGenerate) { Text("Сгенерировать") }
            }
        },
        confirmButton = { Button(onClick = onConfirm) { Text("Сохранить") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}

@Composable
fun ConfirmDialog(text: String, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        text = { Text(text) },
        confirmButton = { Button(onClick = onConfirm) { Text("Удалить") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}
