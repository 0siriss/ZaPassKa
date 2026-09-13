package com.zapasska.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.CloudDone
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zapasska.ui.Strings.tr

/** Unlock, or create the first vault on this phone. */
@Composable
fun LoginScreen(
    password: String,
    onPasswordChange: (String) -> Unit,
    confirm: String,
    onConfirmChange: (String) -> Unit,
    creating: Boolean,
    canToggleCreate: Boolean,
    busy: String?,
    message: String?,
    driveConnected: Boolean,
    onUnlock: () -> Unit,
    onCreate: () -> Unit,
    onToggleCreate: () -> Unit,
    onConnectDrive: () -> Unit,
    onSwitchLanguage: () -> Unit,
    biometricOffered: Boolean,
    onBiometricUnlock: () -> Unit,
) {
    var revealed by remember { mutableStateOf(false) }
    val submit = if (creating) onCreate else onUnlock

    Column(
        modifier = Modifier.fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .imePadding()
            .padding(horizontal = 24.dp),
        verticalArrangement = Arrangement.Top,
    ) {
        Spacer(Modifier.height(48.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("🔐", fontSize = 34.sp)
            Spacer(Modifier.width(12.dp))
            Column {
                Text(tr("Password Vault"), fontSize = 22.sp,
                     fontWeight = FontWeight.Bold, color = Palette.Text)
                Text(tr("AES-256-GCM encrypted"), fontSize = 12.sp,
                     color = Palette.TextDim)
            }
        }

        Spacer(Modifier.height(28.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = Palette.Panel),
        ) {
            Column(Modifier.padding(20.dp)) {
                OutlinedTextField(
                    value = password,
                    onValueChange = onPasswordChange,
                    label = {
                        Text(tr(if (creating) "New master password" else "Master password"))
                    },
                    singleLine = true,
                    visualTransformation =
                        if (revealed) VisualTransformation.None
                        else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = { revealed = !revealed }) {
                            Icon(
                                if (revealed) Icons.Default.VisibilityOff
                                else Icons.Default.Visibility,
                                contentDescription = tr(if (revealed) "Hide" else "Show"),
                                tint = Palette.TextDim,
                            )
                        }
                    },
                    keyboardOptions = KeyboardOptions(
                        imeAction = if (creating) ImeAction.Next else ImeAction.Go),
                    keyboardActions = KeyboardActions(onGo = { submit() }),
                    modifier = Modifier.fillMaxWidth(),
                )

                if (creating) {
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(
                        value = confirm,
                        onValueChange = onConfirmChange,
                        label = { Text(tr("Repeat password")) },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Go),
                        keyboardActions = KeyboardActions(onGo = { submit() }),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(10.dp))
                    Text(
                        tr("A forgotten master password cannot be recovered: it is "
                           + "never stored, it only unwraps the vault key."),
                        color = Palette.TextDim, fontSize = 12.sp,
                    )
                }

                if (message != null) {
                    Spacer(Modifier.height(12.dp))
                    Text(message, color = Palette.Danger, fontSize = 13.sp)
                }

                Spacer(Modifier.height(18.dp))
                Button(
                    onClick = submit,
                    enabled = busy == null,
                    modifier = Modifier.fillMaxWidth().height(50.dp),
                ) {
                    if (busy != null) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary,
                        )
                        Spacer(Modifier.width(10.dp))
                        Text(busy)
                    } else {
                        Text(tr(if (creating) "Create vault" else "Unlock"),
                             fontWeight = FontWeight.SemiBold)
                    }
                }

                if (biometricOffered) {
                    Spacer(Modifier.height(10.dp))
                    OutlinedButton(
                        onClick = onBiometricUnlock,
                        enabled = busy == null,
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                    ) {
                        Icon(Icons.Default.Fingerprint, contentDescription = null,
                             tint = Palette.Accent, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(10.dp))
                        Text(tr("Unlock with fingerprint"))
                    }
                }

                if (canToggleCreate) {
                    Spacer(Modifier.height(4.dp))
                    TextButton(
                        onClick = onToggleCreate,
                        enabled = busy == null,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(tr(if (creating) "I already have a vault"
                                else "Create a new vault"))
                    }
                }
            }
        }

        Spacer(Modifier.height(16.dp))

        OutlinedButton(
            onClick = onConnectDrive,
            enabled = busy == null,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(
                if (driveConnected) Icons.Default.CloudDone else Icons.Default.Cloud,
                contentDescription = null,
                tint = if (driveConnected) Palette.Success else Palette.TextDim,
                modifier = Modifier.size(18.dp),
            )
            Spacer(Modifier.width(10.dp))
            Text(tr(if (driveConnected) "Drive connected" else "Connect Google Drive"))
        }

        Box(Modifier.weight(1f).fillMaxWidth()) {
            TextButton(
                onClick = onSwitchLanguage,
                modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 16.dp),
            ) {
                Text(Strings.other(), color = Palette.TextDim,
                     fontWeight = FontWeight.SemiBold)
            }
        }
    }
}
