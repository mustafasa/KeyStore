package com.example.arifm2.keystore;

import android.content.Context;
import android.content.SharedPreferences;

import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class MainActivity extends AppCompatActivity {

    //Alias is more like key in map, for Keystore
    private static final String ALIAS = "Alias";
    private static final String KEYSTORE_FILE = "bs.keystore";
    private KeyStore keyStore;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final String filePath = getApplication().getFilesDir().getAbsolutePath() + "/" + KEYSTORE_FILE;

        //Creating shareprefernce to store public key, because it's not likely to store in Keystore
        SharedPreferences sharedpreferences = getSharedPreferences(ALIAS, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor= sharedpreferences.edit();;

        try {
            //@method createKeyStore is responsibile to get the instance of keystore
            keyStore = createKeyStore(filePath);
            //////////////optional security parameter
            final KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(
                    getKeystorePassword().toCharArray());

            //Fetch private key from keystore by passing ALIAS and keypassword,if exists
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                    ALIAS, keyPassword);
            //without optional keypassword
//            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
//                    ALIAS, null);

            //if the keystore was instantiated before then it'll be null
            if (entry == null) {
                Log.d("TEST", "null");
                //Generating public and private key by using @method generateRSAKeys
                KeyPair kp=generateRSAKeys();
                PublicKey publicKey =  kp.getPublic();
                PrivateKey privateKey = kp.getPrivate();

                //creating certificate
                X509Certificate certificate = generateCertificate( kp );
                keyStore.setKeyEntry(ALIAS, privateKey, getKeystorePassword().toCharArray(),
                        new Certificate[] { certificate });

                //once the key is genertaed and set in keystore
                //we need to write to a private file
                try (final FileOutputStream fos = new FileOutputStream(filePath)) {
                    //if use @method getKeystorePassword() and keep it null, file will not be secure
                    keyStore.store(fos, getKeystorePassword().toCharArray());
                }
                //converting public key to string and saving in sharedprefenece
                byte[] publicKeyBytes = publicKey.getEncoded();
                String pubKeyStr = new String(Base64.encode(publicKeyBytes,0));
                editor.putString("pub",pubKeyStr);
                editor.commit();

                //Fetch private key from keystore by passing ALIAS and keypassword
                entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                        ALIAS, keyPassword);
            }
            //convert Keystore entry to privatekey
            final PrivateKey GetPrivateKeyFromKeyStore = entry.getPrivateKey();

            //get public key string from sharedpreferences and converting to publicKey
            String pub=sharedpreferences.getString("pub","Default");
            byte[] publicBytes = Base64.decode(pub,0);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
            //now testing here with  @Encrypt and @Decrypt
            String StringToBeEncrypted = "Welcome to KeyStore";
            byte[] AfterEncryption = Encrypt(StringToBeEncrypted,pubKey);
            Log.d("TEST after Encypt", new String(AfterEncryption));
            Log.d("TEST after Decrypt", Decrypt(AfterEncryption, GetPrivateKeyFromKeyStore));

        }  catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }   catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }  catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }


    }

    public static KeyPair generateRSAKeys(){

        KeyPair keyPair = null;
        try {
            // get instance of rsa cipher
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);            // initialize key generator
            keyPair = keyGen.generateKeyPair(); // generate pair of keys
        } catch(GeneralSecurityException e) {
            System.out.println(e);
        }
        return keyPair;
        }

    public static byte[] Encrypt (String plain, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[]  encryptedBytes = cipher.doFinal(plain.getBytes());
        return encryptedBytes;


    }

    public static String Decrypt (byte[] EncyptedBytes,PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {

        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(EncyptedBytes);
        return new String(decryptedBytes);

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

    private static X509Certificate generateCertificate( KeyPair keyPair )
            throws OperatorCreationException, CertificateException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException
    {
        String issuerString = "C=DE, O=datenkollektiv, OU=Planets Debug Certificate";
        // subjects name - the same as we are self signed.
        String subjectString = "C=DE, O=datenkollekitv, OU=Planets Debug Certificate";
        X500Name issuer = new X500Name( issuerString );
        BigInteger serial = BigInteger.ONE;
        Date notBefore = new Date();
        Date notAfter = new Date( System.currentTimeMillis() + ( 10000 ) );
        X500Name subject = new X500Name( subjectString );
        PublicKey publicKey = keyPair.getPublic();
        JcaX509v3CertificateBuilder v3Bldr = new JcaX509v3CertificateBuilder( issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                publicKey );
        X509CertificateHolder certHldr = v3Bldr
                .build( new JcaContentSignerBuilder( "SHA1WithRSA" ).setProvider( "BC" ).build( keyPair.getPrivate() ) );
        X509Certificate cert = new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( certHldr );
        cert.checkValidity( new Date() );
        cert.verify( keyPair.getPublic() );
        return cert;
    }

}
