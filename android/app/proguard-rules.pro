# Release builds are unsigned and not minified. These rules keep UniFFI and
# JNA usable if shrinking is turned on later.
-keep class uniffi.agentlink_ffi.** { *; }
-keep class com.sun.jna.** { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
