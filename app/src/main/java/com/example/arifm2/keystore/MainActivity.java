package com.example.arifm2.keystore;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class MainActivity extends AppCompatActivity {

    //alias is more like key in map
    private static final String ALIAS = "Alias";
    private static final String KEYSTORE_FILE = "bs.keystore";
    private KeyStore keyStore;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final String filePath = getApplication().getFilesDir().getAbsolutePath() + "/" + KEYSTORE_FILE;


        try {


            //createKeyStore is responsibile to get the instance of keystore
            keyStore = createKeyStore(filePath);
            //////////////optional secuity parameter
            final KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(
                    getKeystorePassword().toCharArray());
            //////////////////

            //fetch key from keystore
            KeyStore.Entry entry = keyStore.getEntry(ALIAS, keyPassword);
            //without optional keypassword
            // KeyStore.Entry entry = keyStore.getEntry(ALIAS, null);

            //if the key is not created before then this
            if (entry == null) {
                Log.d("TEST", "null");
                SecretKey GenertaedSk = generateKey();//generate random key
                final KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(
                        GenertaedSk);// converted GenertaedSk to SecretKeyEntry

                //store  key in keystore
                keyStore.setEntry(ALIAS, keyStoreEntry, keyPassword);
                //without optional keypassword
                // keyStore.setEntry(ALIAS, keyStoreEntry, null);

                //once the key is genertaed and enter in keystore
                //we need to write to  a file
                try (final FileOutputStream fos = new FileOutputStream(filePath)) {
                    //if dont povide getKeystorePassword() and keep it null, this file will not be secure
                    keyStore.store(fos, getKeystorePassword().toCharArray());
                }

                entry = keyStore.getEntry(ALIAS, keyPassword);
            }
            //this is for demo purpose just to show using key to encrypt and decrypt
            //convert Entry to Secretkey and send to those methods
            final SecretKey GetsecretKeyFromKeyStore = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
            Log.d("TEST", Base64.encodeToString(GetsecretKeyFromKeyStore.getEncoded(), Base64.DEFAULT));
            String StringToBeEncrypted = "Welcome to KeyStore";
            byte[] AfterEncryption = encryptMsg(StringToBeEncrypted, GetsecretKeyFromKeyStore);
            Log.d("TEST", new String(AfterEncryption));
            Log.d("TEST", decryptMsg(AfterEncryption, GetsecretKeyFromKeyStore));


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    //this guy generate securekey for Encrypt and Dcrypt
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        return kg.generateKey();
    }

    public static byte[] encryptMsg(String message, SecretKey secret)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher cipher =  Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        byte[] cipherText = cipher.doFinal(message.getBytes("UTF-8"));
        return cipherText;
    }

    public static String decryptMsg(byte[] cipherText, SecretKey secret)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        Cipher cipher = null;
        cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret);
        String decryptString = new String(cipher.doFinal(cipherText), "UTF-8");
        return decryptString;
    }


    private String getKeystorePassword() {
        return "this a key is optional, it can utilized more secure";
    }


    private KeyStore createKeyStore(@NonNull final String fileName)
            throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        final File file = new File(fileName);

        final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        if (file.exists()) {
            // .keystore file already exists => load it
            final FileInputStream inputStream = new FileInputStream(file);
            //provide file and password to open the file
            keyStore.load(inputStream, getKeystorePassword().toCharArray());
            inputStream.close();
        } else {
            //.keystore file not created yet => create it
            //we're creating at create method
            //this file has to be created, as without this keystore doesn't save keys
            keyStore.load(null, null);
        }

        return keyStore;
    }


}
