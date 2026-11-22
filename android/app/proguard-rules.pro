# Release builds are unsigned and not minified. These rules keep UniFFI,
# JNA, and Shizuku reflection usable if shrinking is turned on later.
-keep class uniffi.agentlink_ffi.** { *; }
-keep class com.sun.jna.** { *; }
-keep class rikka.shizuku.** { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
