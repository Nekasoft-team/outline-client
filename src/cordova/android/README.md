# Android Development Instructions

This document describes how to develop and debug for Android.

The main entrypoint to Android's Java code is `cordova-plugin-outline/android/java/org/outline/OutlinePlugin.java`

## Building the Android app

Additional requirements for Android:

- [Java Development Kit (JDK) 11](https://jdk.java.net/archive/)
  - Set `JAVA_HOME` environment variable if you are building on Windows
- Latest [Android Sdk Commandline Tools](https://developer.android.com/studio/command-line) ([download](https://developer.android.com/studio#command-line-tools-only))
  - Place it at `$HOME/Android/sdk/cmdline-tools/latest`
  - Set `ANDROID_HOME` environment variable
- Android SDK 32 (with build-tools) via commandline `$HOME/Android/sdk/cmdline-tools/latest/bin/sdkmanager "platforms;android-32" "build-tools;32.0.0"`
- [Gradle 7.3+](https://gradle.org/install/)

[Android Studio 2020.3.1+](https://developer.android.com/studio) is not required, but it's helpful if you are developing Android code.

> 💡 NOTE: During one of the steps can be required to install `Visual Studio` (attention, not `Visual Studio Code`) with `Desktop development with C++`. You can get it free from official website.

To build for android, run:

```sh
  npm run action cordova/build android
```

We also support passing a `--verbose` option on cordova android:

```sh
  npm run action cordova/build android -- --verbose
```

Make sure to rebuild after modifying platform dependent files!

> 💡 NOTE: If this command ever gives you unexpected Cordova errors, try runnning `npm run reset` first.

Cordova will generate a new Android project in the platforms/android directory. Install the built apk by `platforms/android/app/build/outputs/apk/<processor>/debug/app-<processor>-debug.apk` (You will need to find the corresponding `<processor>` architecture if you choose to install the apk on a device).

### To debug Java code

Using Android Studio

- Open Android Studio
- Go to Debug APK (File → Profile or Debug APK)
- Open existing APK → `<root_project_dir>/platforms/android/app/build/outputs/apk/debug/app-debug.apk`
- Java code is in directory `java`
- Open the java file of interest
- Click the button `Attach Kotlin/Java Sources` in the message on the top of screen
- Find directory with source file in root project directory. You can choise the whole root project directory, then Android Studio will search source file by himself, but it can last enough long time
- After this Android Studio will open java file instead of smali file. Here you can set up breakpoints

### Links

- Specification: https://docs.google.com/document/d/1JAtLO_3Hm_IvNQgB4VnjB40TS0GeOE06shnpAAuWny4/edit#heading=h.9ztqw2g799v1
- Original Outline client repo: https://github.com/Jigsaw-Code/outline-client
- X-Ray repo: https://github.com/XTLS/Xray-core
- X-Ray InboindObject documentation: https://xtls.github.io/config/inbound.html#inboundobject
- Convert XTLS/Xray-core to .aar (ChatGPT conversation): https://chat.openai.com/share/420a76d1-fba5-4ebc-9574-e2922231dfda
