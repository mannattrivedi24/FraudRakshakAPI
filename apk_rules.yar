/*
  apk_rules_final.yar
  --- HIGHLY TUNED FOR MINIMAL FALSE POSITIVES ---
*/

rule High_Confidence_Secrets
{
    meta:
        author = "scanner"
        description = "Detects high-confidence hardcoded secrets and API keys like AWS and Google."
        severity = "critical"
    strings:
        $aws_ak = /AKIA[0-9A-Z]{16}/
        $google_api = /AIza[0-9A-Za-z\-_]{35}/
        $slack_bot = /xoxb-[0-9]{8,}-[0-9A-Za-z]{24,}/
        $slack_user = /xoxp-[0-9]{8,}-[0-9A-Za-z]{24,}/
        $pem_priv = "-----BEGIN PRIVATE KEY-----"
        $pem_rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $pem_ec = "-----BEGIN EC PRIVATE KEY-----"
    condition:
        any of them
}

rule Suspicious_Network_Endpoints
{
    meta:
        author = "scanner"
        description = "Detects suspicious URLs, TLDs, tunneling services, and Tor addresses."
        severity = "medium"
    strings:
        $onion   = /\.onion\b/ nocase
        $ngrok   = "ngrok.io" nocase
        $serveo  = "serveo.net" nocase
        
        /* --- TUNED: This regex is now more compatible. ---
           It looks for a quote or whitespace before the TLD to avoid 'variable.top' false positives.
        */
        $bad_tld = /["'\s]\.(xyz|top|club|online|site|pw|tk|ml|ga|cf|gq)\b/ nocase
        
        $paste = /(pastebin|gist.github|hastebin|dpaste|0x0)\./ nocase
    condition:
        any of them
}

rule Suspicious_Permissions
{
    meta:
        author = "scanner"
        description = "Detects high-risk Android permissions declared in the code or manifest."
        severity = "high"
    strings:
        $send_sms = "android.permission.SEND_SMS"
        $read_sms = "android.permission.READ_SMS"
        $read_contacts = "android.permission.READ_CONTACTS"
        $storage = "android.permission.WRITE_EXTERNAL_STORAGE"
        $camera = "android.permission.CAMERA"
        $mic = "android.permission.RECORD_AUDIO"
        $location = "android.permission.ACCESS_FINE_LOCATION"
        $call_log = "android.permission.READ_CALL_LOG"
    condition:
        any of them
}

rule Weak_Crypto_Usage
{
    meta:
        author = "scanner"
        description = "Detects use of weak hashing algorithms and insecure cipher modes."
        severity = "medium"
    strings:
        $md5 = "MessageDigest.getInstance(\"MD5\")" nocase
        $sha1 = "MessageDigest.getInstance(\"SHA-1\")" nocase
        $sha1_alt = "MessageDigest.getInstance(\"SHA1\")" nocase
        $ecb = /Cipher\.getInstance\([^\)]*ECB[^\)]*\)/ nocase
    condition:
        any of them
}

rule Manifest_Security_Risks
{
    meta:
        author = "scanner"
        description = "Detects risky manifest flags like debuggable and allowBackup."
        severity = "medium"
    strings:
        $debuggable = "android:debuggable=\"true\"" nocase
        $allow_backup = "android:allowBackup=\"true\"" nocase
        $exported_true = "android:exported=\"true\"" nocase
    condition:
        any of them
}

rule Suspicious_Embedded_Files
{
    meta:
        author = "scanner"
        description = "Detects suspicious file types in the assets directory, a common place for payloads."
        severity = "medium"
    strings:
        $assets_dex = /assets\/[^\s]+\.dex\b/i
        $assets_jar = /assets\/[^\s]+\.jar\b/i
        $assets_zip = /assets\/[^\s]+\.zip\b/i
        $assets_enc = /(assets|res\/raw)\/.*\.(enc|bin|dat|datx)\b/i
        $native_lib = /lib\/[a-zA-Z0-9_\-]+\.so/ nocase
    condition:
        any of them
}