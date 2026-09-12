# ZaPassKa для Android

Клиент на Kotlin и Jetpack Compose. Работает с тем же хранилищем, что и
десктопная версия: формат описан в [docs/FORMAT.md](../docs/FORMAT.md), а
совместимость проверяется тестом против общих эталонных векторов.

Вход только по мастер-паролю. Телефон обычно вне корпоративной сети, до
контроллера домена не достучаться, поэтому хранилище на доменной учётке на
телефоне не откроется. Переведите его на мастер-пароль в разделе «Защита»
десктопного приложения.

## Сборка

```bash
cd android
gradle :app:testDebugUnitTest :app:assembleDebug
```

## Ключ подписи

Google привязывает OAuth-клиент типа Android к отпечатку сертификата, которым
подписан APK. Отладочный ключ у каждой машины свой, а на runner'е GitHub он
вообще создаётся заново при каждом запуске, поэтому для работы с Диском нужен
один постоянный ключ.

Создайте его один раз и храните надёжно: потеряете, и обновления придётся
ставить только со сносом приложения.

```bash
keytool -genkeypair -v -keystore zapasska.jks -alias zapasska \
        -keyalg RSA -keysize 4096 -validity 10000
```

Отпечаток, который нужно указать в Google Cloud:

```bash
keytool -list -v -keystore zapasska.jks -alias zapasska | grep SHA1
```

Значение для секрета репозитория:

```bash
base64 -w0 zapasska.jks          # macOS: base64 -i zapasska.jks | tr -d '\n'
```

## Секреты репозитория

| Секрет | Обязателен | Зачем |
|---|---|---|
| `ANDROID_GOOGLE_CLIENT_ID` | для работы с Диском | OAuth-клиент типа Android, package `com.zapasska` |
| `ANDROID_KEYSTORE_BASE64` | для подписанной сборки | содержимое `zapasska.jks` в base64 |
| `ANDROID_KEYSTORE_PASSWORD` | вместе с предыдущим | пароль хранилища ключей |
| `ANDROID_KEY_ALIAS` | вместе с предыдущим | псевдоним ключа, в примере `zapasska` |
| `ANDROID_KEY_PASSWORD` | вместе с предыдущим | пароль ключа |

Без секретов подписи собирается отладочный APK, и Диск в нём работать не
будет: отпечаток не совпадёт с зарегистрированным.

Отпечаток собранного APK печатается в логе сборки, шагом
«Report the certificate the APK was signed with». По нему удобно сверяться с
тем, что указано в Google Cloud.
