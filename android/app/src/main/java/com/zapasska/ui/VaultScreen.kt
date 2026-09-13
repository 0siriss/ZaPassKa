package com.zapasska.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Casino
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zapasska.data.Entry
import com.zapasska.ui.Strings.tr

@Composable
fun VaultScreen(
    entries: List<Entry>,
    total: Int,
    query: String,
    onQueryChange: (String) -> Unit,
    revealed: String?,
    syncStatus: String,
    syncing: Boolean,
    onToggleReveal: (String) -> Unit,
    onCopy: (Entry) -> Unit,
    onEdit: (Entry) -> Unit,
    onDelete: (Entry) -> Unit,
    onAdd: () -> Unit,
    onSync: () -> Unit,
    onLock: () -> Unit,
    onSwitchLanguage: () -> Unit,
    biometricAvailable: Boolean,
    biometricEnabled: Boolean,
    onToggleBiometric: () -> Unit,
) {
    Box(Modifier.fillMaxSize().background(Palette.Background)) {
        Column(Modifier.fillMaxSize()) {

            Row(
                modifier = Modifier.fillMaxWidth()
                    .background(Palette.Panel)
                    .statusBarsPadding()
                    .padding(start = 20.dp, end = 8.dp, top = 12.dp, bottom = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text(tr("Vault"), fontSize = 20.sp,
                         fontWeight = FontWeight.Bold, color = Palette.Text)
                    Text(tr("%d entries", total), fontSize = 12.sp, color = Palette.TextDim)
                }
                if (biometricAvailable) {
                    IconButton(onClick = onToggleBiometric) {
                        Icon(
                            Icons.Default.Fingerprint,
                            contentDescription = tr("Fingerprint"),
                            tint = if (biometricEnabled) Palette.Accent
                                   else Palette.TextDim,
                        )
                    }
                }
                IconButton(onClick = onSync, enabled = !syncing) {
                    Icon(Icons.Default.Cloud, contentDescription = tr("Sync"),
                         tint = if (syncing) Palette.Border else Palette.TextDim)
                }
                TextButton(onClick = onSwitchLanguage) {
                    Text(Strings.other(), color = Palette.TextDim, fontSize = 13.sp,
                         fontWeight = FontWeight.SemiBold)
                }
                IconButton(onClick = onLock) {
                    Icon(Icons.Default.Lock, contentDescription = tr("Lock"),
                         tint = Palette.TextDim)
                }
            }

            Column(Modifier.padding(horizontal = 16.dp).imePadding()) {
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = query,
                    onValueChange = onQueryChange,
                    placeholder = { Text(tr("Search"), color = Palette.TextDim) },
                    leadingIcon = {
                        Icon(Icons.Default.Search, contentDescription = null,
                             tint = Palette.TextDim, modifier = Modifier.size(20.dp))
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                Text(syncStatus, color = Palette.TextDim, fontSize = 11.sp)
            }

            if (entries.isEmpty()) {
                Text(
                    tr(if (total == 0)
                           "Nothing here yet. Add the first entry with the button below."
                       else "Nothing found"),
                    color = Palette.TextDim, fontSize = 14.sp,
                    modifier = Modifier.padding(24.dp),
                )
            }

            LazyColumn(
                modifier = Modifier.fillMaxSize().navigationBarsPadding(),
                contentPadding = PaddingValues(16.dp, 8.dp, 16.dp, 96.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                items(entries, key = { it.uuid }) { entry ->
                    EntryCard(
                        entry = entry,
                        revealed = entry.uuid == revealed,
                        onToggleReveal = { onToggleReveal(entry.uuid) },
                        onCopy = { onCopy(entry) },
                        onEdit = { onEdit(entry) },
                        onDelete = { onDelete(entry) },
                    )
                }
            }
        }

        FloatingActionButton(
            onClick = onAdd,
            containerColor = Palette.Accent2,
            contentColor = androidx.compose.ui.graphics.Color.White,
            modifier = Modifier.align(Alignment.BottomEnd)
                .navigationBarsPadding()
                .padding(20.dp),
        ) {
            Icon(Icons.Default.Add, contentDescription = tr("Add"))
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
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Palette.Panel),
    ) {
        Column(Modifier.padding(start = 16.dp, end = 6.dp, top = 12.dp, bottom = 4.dp)) {
            Text(entry.service, color = Palette.Text, fontSize = 16.sp,
                 fontWeight = FontWeight.SemiBold, maxLines = 1)
            Text(entry.login, color = Palette.TextDim, fontSize = 13.sp, maxLines = 1)

            Spacer(Modifier.height(6.dp))
            Text(
                if (revealed) entry.password else "••••••••••••",
                color = if (revealed) Palette.Accent else Palette.TextDim,
                fontSize = 15.sp,
                fontFamily = if (revealed) FontFamily.Monospace else FontFamily.Default,
                maxLines = 1,
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(onClick = onToggleReveal) {
                    Icon(
                        if (revealed) Icons.Default.VisibilityOff
                        else Icons.Default.Visibility,
                        contentDescription = tr(if (revealed) "Hide" else "Show"),
                        tint = if (revealed) Palette.Accent else Palette.TextDim,
                    )
                }
                IconButton(onClick = onCopy) {
                    Icon(Icons.Default.ContentCopy, contentDescription = tr("Copy"),
                         tint = Palette.TextDim)
                }
                IconButton(onClick = onEdit) {
                    Icon(Icons.Default.Edit, contentDescription = tr("Edit"),
                         tint = Palette.TextDim)
                }
                IconButton(onClick = onDelete) {
                    Icon(Icons.Default.Delete, contentDescription = tr("Delete"),
                         tint = Palette.Danger)
                }
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
        containerColor = Palette.Panel,
        title = { Text(title, color = Palette.Text) },
        text = {
            Column {
                OutlinedTextField(service, onServiceChange, singleLine = true,
                                  label = { Text(tr("Service")) },
                                  modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(login, onLoginChange, singleLine = true,
                                  label = { Text(tr("Login")) },
                                  modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    password, onPasswordChange, singleLine = true,
                    label = { Text(tr("Password")) },
                    trailingIcon = {
                        IconButton(onClick = onGenerate) {
                            Icon(Icons.Default.Casino,
                                 contentDescription = tr("Generate"),
                                 tint = Palette.Accent)
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = { Button(onClick = onConfirm) { Text(tr("Save")) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(tr("Cancel")) } },
    )
}

@Composable
fun ConfirmDialog(text: String, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Palette.Panel,
        text = { Text(text, color = Palette.Text) },
        confirmButton = {
            Button(onClick = onConfirm) { Text(tr("Delete")) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(tr("Cancel")) } },
    )
}
