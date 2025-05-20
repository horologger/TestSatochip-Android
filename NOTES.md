# Clean prior to build
./gradlew clean

# Build with gradle
./gradlew assemble

# Check for connected device
adb devices -l

# Install APK on connected device
adb install -r app/build/outputs/apk/debug/app-debug.apk

# Uninstall APK from device
adb uninstall org.satochip.testsatochip

# Display all gradle tasks
./gradlew tasks

