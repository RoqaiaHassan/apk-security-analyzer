import os
import zipfile
import shutil

TEST_DIR = os.path.dirname(__file__)

def generate_sample_apks():
    samples_dir = os.path.join(TEST_DIR, "sample_apks")
    os.makedirs(samples_dir, exist_ok=True)

    # 1. TestApp_AES_ECB.apk
    path_ecb = os.path.join(samples_dir, "TestApp_AES_ECB.apk")
    with zipfile.ZipFile(path_ecb, 'w') as zipf:
        manifest = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.crypto.aecb" android:debuggable="true">
            <uses-permission android:name="android.permission.INTERNET"/>
            <uses-permission android:name="android.permission.CAMERA"/>
            <application android:allowBackup="true" android:label="TestApp ECB">
                <activity android:name=".MainActivity" android:exported="true"/>
            </application>
        </manifest>"""
        zipf.writestr("AndroidManifest.xml", manifest)
        
        # Fake DEX content with weak AES/ECB pattern
        dex_code = b"""
        Lcom/crypto/aecb/CryptoManager;
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec("my_super_secret_key_123".getBytes(), "AES");
        MessageDigest.getInstance("MD5");
        String api_url = "http://api.insecure-server.com/v1/login";
        String google_key = "AIzaSyDummyTestKeyForTestingSecretsEngine12";
        """
        zipf.writestr("classes.dex", dex_code)
        zipf.writestr("META-INF/CERT.RSA", b"CERTIFICATE_DATA")

    # 2. TestApp_DES_3DES.apk
    path_des = os.path.join(samples_dir, "TestApp_DES_3DES.apk")
    with zipfile.ZipFile(path_des, 'w') as zipf:
        manifest = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.crypto.desapp">
            <uses-permission android:name="android.permission.READ_SMS"/>
            <application android:allowBackup="true">
                <activity android:name=".MainActivity"/>
            </application>
        </manifest>"""
        zipf.writestr("AndroidManifest.xml", manifest)
        
        dex_code = b"""
        Cipher.getInstance("DES/CBC/PKCS5Padding");
        Cipher.getInstance("DESede/ECB/NoPadding");
        MessageDigest.getInstance("SHA-1");
        String admin_pass = "admin_password=SuperSecretPass123!";
        """
        zipf.writestr("classes.dex", dex_code)

    # 3. TestApp_Secure.apk
    path_secure = os.path.join(samples_dir, "TestApp_Secure.apk")
    with zipfile.ZipFile(path_secure, 'w') as zipf:
        manifest = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.crypto.secure" android:debuggable="false">
            <application android:allowBackup="false">
                <activity android:name=".MainActivity" android:exported="false"/>
            </application>
        </manifest>"""
        zipf.writestr("AndroidManifest.xml", manifest)
        
        dex_code = b"""
        Cipher.getInstance("AES/GCM/NoPadding");
        KeyGenParameterSpec.Builder builder;
        MessageDigest.getInstance("SHA-256");
        String api_url = "https://secure.api-endpoint.com/v1/";
        """
        zipf.writestr("classes.dex", dex_code)

    print(f"[*] Generated 3 sample APKs in: {samples_dir}")

if __name__ == "__main__":
    generate_sample_apks()
