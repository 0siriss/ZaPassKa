package com.zapasska.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Unlock, or create the first vault on this phone. */
@Composable
fun LoginScreen(
    password: String,
    onPasswordChange: (String) -> Unit,
    confirm: String,
    onConfirmChange: (String) -> Unit,
    creating: Boolean,
    hasVault: Boolean,
    busy: String?,
    message: String?,
    driveConnected: Boolean,
    onUnlock: () -> Unit,
    onCreate: () -> Unit,
    onToggleCreate: () -> Unit,
    onConnectDrive: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text("🔐  Хранилище паролей", fontSize = 24.sp, fontWeight = FontWeight.Bold,
             color = Palette.Text)
        Spacer(Modifier.height(4.dp))
        Text("Шифрование AES-256-GCM", color = Palette.TextDim, fontSize = 13.sp)
        Spacer(Modifier.height(28.dp))

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp)) {
                OutlinedTextField(
                    value = password,
                    onValueChange = onPasswordChange,
                    label = { Text(if (creating) "Новый мастер-пароль" else "Мастер-пароль") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                    modifier = Modifier.fillMaxWidth(),
                )

                if (creating) {
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(
                        value = confirm,
                        onValueChange = onConfirmChange,
                        label = { Text("Повторите пароль") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Забытый мастер-пароль восстановить нельзя: он нигде не " +
                            "хранится и нужен только для разворачивания ключа.",
                        color = Palette.TextDim, fontSize = 12.sp,
                    )
                }

                message?.let {
                    Spacer(Modifier.height(12.dp))
                    Text(it, color = Palette.Danger, fontSize = 13.sp)
                }

                Spacer(Modifier.height(20.dp))
                Button(
                    onClick = if (creating) onCreate else onUnlock,
                    enabled = busy == null,
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                ) {
                    if (busy != null) {
                        CircularProgressIndicator(
                            modifier = Modifier.height(18.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary,
                        )
                        Spacer(Modifier.height(0.dp))
                        Text("  $busy")
                    } else {
                        Text(if (creating) "Создать хранилище" else "Открыть")
                    }
                }

                if (!hasVault || creating) {
                    TextButton(onClick = onToggleCreate, enabled = busy == null) {
                        Text(if (creating) "У меня уже есть хранилище"
                             else "Создать новое хранилище")
                    }
                }
            }
        }

        Spacer(Modifier.height(20.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onConnectDrive, enabled = busy == null) {
                Text(if (driveConnected) "☁ Диск подключён"
                     else "☁ Подключить Google Диск", color = Palette.TextDim)
            }
        }
        if (!hasVault && driveConnected) {
            Text(
                "Хранилищ на этом телефоне нет. Если они есть на компьютере, " +
                    "нажмите «Подключить Google Диск», чтобы скачать их.",
                color = Palette.TextDim, fontSize = 12.sp,
            )
        }
    }
}
