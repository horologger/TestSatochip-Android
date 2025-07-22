# Build and run the app
```
./gradlew assembleDebug -x lint 
adb install app/build/outputs/apk/debug/app-debug.apk 
adb shell am start -n org.satochip.testsatochip/.MainActivity 
adb logcat | grep -E "(NFC|Satochip|TestSatochip)"
```