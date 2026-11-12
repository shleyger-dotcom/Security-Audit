# Java and Kotlin (JVM, Spring): dangerous sinks and safe replacements

Kotlin uses the same APIs. For Android code, also load `mobile.md`.

## Deserialization and XML

| Dangerous on untrusted data | Why | Safe |
|---|---|---|
| `ObjectInputStream.readObject`, `XMLDecoder`, Kryo with class registration off | gadget chains give remote code execution (CWE-502) | JSON with fixed target types; `ObjectInputFilter` allowlist if Java serialization is unavoidable |
| Jackson `enableDefaultTyping()`, `activateDefaultTyping`, `@JsonTypeInfo(use = Id.CLASS)` | the input selects the class | fixed types; `@JsonTypeInfo(use = Id.NAME)` with `@JsonSubTypes` |
| SnakeYAML `new Yaml().load(input)` (versions before 2.0) | creates any object | `new Yaml(new SafeConstructor(new LoaderOptions()))` |
| XStream without an allowlist | creates any object | `xstream.allowTypes(...)` |
| `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory` with defaults | XXE (CWE-611) | `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`; for StAX `SUPPORT_DTD = false`; `setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")` |

## Injection

- SQL: `Statement` with string concatenation, `createQuery("... " + x)` (JPQL/HQL), `createNativeQuery("... " + x)`, `JdbcTemplate.query("... " + x)` → `PreparedStatement` or named parameters.
- MyBatis: `${value}` inserts text → `#{value}`. For `ORDER BY`, use an allowlist.
- Spring Data `@Query` with string concatenation or SpEL on input.
- OS commands: `Runtime.exec(String)`, `ProcessBuilder("sh", "-c", input)` → `new ProcessBuilder("prog", arg1, arg2)`.
- Expression languages: `SpelExpressionParser.parseExpression(input)`, OGNL, MVEL, JSP EL, `ScriptEngine.eval(input)` → never evaluate input (CWE-917).
- JNDI: `InitialContext.lookup(input)` loads remote code. Log4j 2 before 2.17.1 does this from log messages (Log4Shell, CVE-2021-44228).
- LDAP filters built by concatenation → encode the value (`LdapEncoder.filterEncode`).

## Files and paths

- `new File(base, user)`, `Paths.get(base, user)` → `Path p = base.resolve(user).normalize(); if (!p.startsWith(base)) throw ...`. Use `toRealPath()` when symlinks matter.
- Zip: check each `ZipEntry.getName()` with the same test (zip slip). Limit the total size.
- `File.createTempFile` in a shared folder → `Files.createTempFile` (owner-only permissions).
- `MultipartFile.getOriginalFilename()` comes from the client: never use it as a path.

## Spring and Spring Boot

- Actuator: `management.endpoints.web.exposure.include=*` opens `/actuator/env`, `/heapdump`, `/loggers`. Expose only `health`, and protect the others.
- Security config: every route needs a rule; end with `anyRequest().authenticated()`. `permitAll()` on a wide matcher such as `/api/**` is a finding.
- Method security: `@PreAuthorize` on service methods that change data of other users. Check object ownership, not only the role.
- `csrf().disable()` together with cookie sessions.
- `@CrossOrigin("*")`, or `allowedOriginPatterns("*")` with `allowCredentials(true)`.
- Mass assignment: a JPA entity used as `@RequestBody` or `@ModelAttribute` → a DTO with only the allowed fields.
- Open redirect: `return "redirect:" + input`.
- View name from input (`return input;` in a controller) → template injection in Thymeleaf.
- Thymeleaf `th:utext` and JSP `<%= %>` print without escaping → `th:text`, `<c:out>`.
- `server.error.include-stacktrace=always`, `spring.h2.console.enabled=true`, `spring-boot-devtools` in a production build.
- Passwords in `application.properties` / `application.yml` → environment or a vault.

## Crypto and randomness

- `java.util.Random`, `Math.random()`, `ThreadLocalRandom` for tokens → `SecureRandom`.
- `Cipher.getInstance("AES")` means ECB → `"AES/GCM/NoPadding"` with a new 12-byte IV for each message.
- `MessageDigest` MD5/SHA-1/SHA-256 for passwords → `BCryptPasswordEncoder`, `Argon2PasswordEncoder`.
- `String.equals` or `Arrays.equals` for tokens and MACs → `MessageDigest.isEqual`.
- A `TrustManager` that accepts every certificate, `HostnameVerifier` that returns `true`, `SSLContext` built from them (CWE-295).
- JWT: the parser must require a signature and a fixed algorithm. A parser that accepts unsigned tokens (`alg: none`) is a finding.

## Other

- `Pattern.compile(input)` or nested quantifiers on input → ReDoS. Java has no regex timeout: limit the input length.
- `HttpClient` / `RestTemplate` / `WebClient` with a user URL → SSRF (see checklist A). Set connect and read timeouts.
- Logging input: Logback and Log4j do not remove CR/LF by default.
- `assert` is off by default at runtime. Do not use it for security checks.
- JNI and `sun.misc.Unsafe` code: see `c-cpp.md`.

## Maven and Gradle

- No dynamic versions (`1.+`, `latest.release`, version ranges). Gradle: commit lockfiles or `gradle/verification-metadata.xml`.
- Repositories use `https://`. A private group ID must not resolve from a public repository first (dependency confusion).
- `gradle-wrapper.jar` is a binary that runs on each build: verify its checksum (`gradle/actions/wrapper-validation` in CI).
- Maven and Gradle plugins and build scripts run code at build time. Do not build an untrusted project outside a sandbox.
