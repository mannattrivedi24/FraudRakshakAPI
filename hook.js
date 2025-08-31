Java.perform(function () {
    console.log("[*] Lightweight hooks started...");

    // --- 1. Network requests ---
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.connect.implementation = function () {
            console.log("[*] Network request: " + this.getURL().toString());
            return this.connect();
        };
    } catch (e) {
        console.log("HttpURLConnection hook error:", e);
    }

    // --- 2. SharedPreferences ---
    try {
        var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
        SharedPreferencesImpl.getString.overload('java.lang.String', 'java.lang.String')
            .implementation = function (key, defVal) {
                var val = this.getString(key, defVal);
                console.log("[*] SharedPreferences GET key=" + key + " val=" + val);
                return val;
            };
    } catch (e) {
        console.log("SharedPreferences hook error:", e);
    }

    // --- 3. File operations ---
    try {
        var FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload('java.io.File').implementation = function (file) {
            console.log("[*] File read: " + file.getAbsolutePath());
            return this.$init(file);
        };

        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload('java.io.File').implementation = function (file) {
            console.log("[*] File write: " + file.getAbsolutePath());
            return this.$init(file);
        };
    } catch (e) {
        console.log("File I/O hook error:", e);
    }

    console.log("[*] Lightweight hooks ready!");
});
