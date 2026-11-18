#!/bin/sh
# Runs the E2E on the emulator; always collects logcat and connectivity dumps, even when Gradle fails.
STATUS=0
./gradlew :testbed:installDebug :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=io.github.leemikepop.trustprobe.e2e.TestbedVerdictsTest || STATUS=$?
mkdir -p e2e-diagnostics
adb logcat -d -v threadtime > e2e-diagnostics/logcat.txt || true
adb shell dumpsys connectivity > e2e-diagnostics/connectivity.txt || true
exit $STATUS
