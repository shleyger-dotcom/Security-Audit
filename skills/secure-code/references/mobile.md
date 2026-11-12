# Mobile apps: Android, iOS, React Native, Flutter

Mapped to the OWASP Mobile Top 10 (2024) and OWASP MASVS.

## Rules for every platform

- The app package is public. Anyone can unpack it and read code, resources and bundled files. Obfuscation (R8, ProGuard, `--obfuscate`) slows this down; it is not a security control.
- No secrets in the app: no paid API keys, signing keys, admin credentials or encryption keys in code, resources, `strings.xml`, `Info.plist`, `BuildConfig`, the JavaScript bundle, or `.env` files of React Native and Flutter. Call third-party APIs through your backend.
- The server enforces authentication, authorization, prices and limits. Checks in the app (root or jailbreak detection, license checks, hidden buttons) can be bypassed.
- Tokens are stored only in the platform key store (Android Keystore, iOS Keychain).
- All traffic uses TLS with certificate checks on. High-risk apps pin the certificate or public key, with a backup pin.
- No tokens, passwords or personal data in logs, crash reports, analytics events, the clipboard or screenshots of sensitive screens.
- Release signing keys (`*.jks`, `*.keystore`, `*.p12`, `*.mobileprovision`) and their passwords are not in git.

## Android

**Manifest**
- `android:exported="true"` on an activity, service, receiver or provider without a `permission` → any app can call it. A component with an intent filter was exported by default before API 31.
- `android:debuggable="true"` or `android:allowBackup="true"` (with private data) in a release build.
- `android:usesCleartextTraffic="true"`, or a network security config that allows cleartext or trusts user certificates (`<certificates src="user"/>`) in release.
- `FileProvider` paths that are too wide: `<root-path>`, `path="."`, `path="/"`.

**Intents and deep links**
- Data from an intent or a deep link is untrusted input. Validate each extra and each URL parameter.
- Intent redirection: `startActivity(intent.getParcelableExtra("next"))` lets another app start private components.
- `PendingIntent` without `FLAG_IMMUTABLE`, or with an empty base intent.
- An implicit intent or broadcast that carries private data: other apps can receive it → an explicit component.
- Authentication callbacks use verified App Links (`android:autoVerify="true"`), not custom schemes.

**WebView**
- `setJavaScriptEnabled(true)` together with `addJavascriptInterface` and content that is not yours: the page can call your Java methods.
- `setAllowFileAccess(true)`, `setAllowUniversalAccessFromFileURLs(true)`, `loadUrl(input)` without a host allowlist.
- `onReceivedSslError` that calls `handler.proceed()`.
- `WebView.setWebContentsDebuggingEnabled(true)` in release.

**Storage and data**
- Tokens or personal data in plain `SharedPreferences`, plain SQLite, or external storage → encrypt with a key from the Android Keystore.
- `MODE_WORLD_READABLE`, `MODE_WORLD_WRITEABLE`.
- SQL: `rawQuery("... " + x)`, `execSQL` with concatenation → `?` placeholders with `selectionArgs`. A `ContentProvider` validates `selection`, `projection` and `sortOrder`, and checks paths in `openFile` (path traversal).
- Sensitive screens set `FLAG_SECURE`.

**Crypto and code loading**
- A `TrustManager` that accepts every certificate, `HostnameVerifier` that returns `true`.
- Hardcoded keys and IVs; `SecureRandom` with a fixed seed; AES in ECB mode.
- `DexClassLoader` or `System.load` on a file from the download folder, external storage or the network.

**Backend configuration that ships with the app**
- Firebase rules that allow all access: `".read": true`, `".write": true`, `allow read, write: if true`.
- `google-services.json` keys are public by design: restrict them in the cloud console (package name, signing certificate, API list).

## iOS

- Tokens in `UserDefaults`, a plist or a plain file → Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (not `kSecAttrAccessibleAlways`). Files use `NSFileProtectionComplete`.
- App Transport Security: `NSAllowsArbitraryLoads = true`, or wide exception domains in `Info.plist`.
- TLS: a `URLSessionDelegate` that accepts every server trust; Alamofire `DisabledTrustEvaluator`.
- URL schemes and Universal Links: validate every parameter in `application(_:open:options:)` and `scene(_:openURLContexts:)`. Another app can register the same custom scheme → Universal Links, and `ASWebAuthenticationSession` with PKCE for OAuth.
- `WKWebView`: `loadHTMLString` with user data; `allowFileAccessFromFileURLs`; a `WKScriptMessageHandler` that does not check the frame origin. `UIWebView` is deprecated.
- Biometrics: a decision made only from the `LAContext.evaluatePolicy` result can be bypassed → protect a Keychain item with `SecAccessControl` (`.biometryCurrentSet`).
- `NSKeyedUnarchiver.unarchiveObject(with:)` on untrusted data → `unarchivedObject(ofClass:from:)` with secure coding.
- `String(format: input)`, `NSPredicate(format: input)`, `NSLog(input)` → the input must be an argument, not the format.
- `UnsafePointer`, `UnsafeMutableRawPointer`, Objective-C and C code: see `c-cpp.md`.
- Password fields use `isSecureTextEntry`. Sensitive screens are hidden in the app switcher snapshot.

## React Native

- `AsyncStorage` is plain text → `react-native-keychain` or `expo-secure-store` for tokens.
- The JavaScript bundle and its `.env` values are readable.
- `Linking` URL parameters are untrusted input.
- `<WebView>`: `originWhitelist={['*']}`, `onMessage` without a check of the sender URL, `injectedJavaScript` built from input.
- Over-the-air updates (CodePush, EAS Update) need code signing.
- JavaScript rules from `javascript.md` apply.

## Flutter

- `shared_preferences` is plain text → `flutter_secure_storage` for tokens.
- `HttpClient.badCertificateCallback = (...) => true` disables TLS checks.
- Platform channel handlers validate arguments from the Dart side and from the native side.
- Values passed with `--dart-define` are inside the binary.
