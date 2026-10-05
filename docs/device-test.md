# Leash Android Build and Verification (M9.1)

## Build Status
- **Date**: Oct 5, 2026
- **Gradle Task**: `./gradlew assembleDebug`
- **Unit Test Task**: `./gradlew testDebugUnitTest`
- **Status**: PASSED
- **Artifact Path**: `android/app/build/outputs/apk/debug/app-debug.apk` (18.3 MB)

## Environment
- **Compile SDK**: 35 (Android 15)
- **Min SDK**: 26 (Android 8.0)
- **Target SDK**: 35
- **Java Runtime**: OpenJDK 17 (Adoptium 17.0.20.1)

## Verification Highlights
- **Golden Vector Alignment**: `GoldenVectorsTest` executed on Android JVM and validated byte-for-byte canonical JSON equivalence with daemon `contracts/golden/canonical_vectors.json`.
- **Security Protocols Verified**:
  - ECDSA P-256 decision signing using canonical JCS JSON bytes (`ensure_ascii=False`).
  - Action digest verification preventing action mismatch tampering.
  - One-time pairing tokens with timeout and rate-limit lockout.
