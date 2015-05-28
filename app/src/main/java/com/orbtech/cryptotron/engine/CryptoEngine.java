package com.orbtech.cryptotron.engine;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.Signature;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/**
 * Created by gavinbr on 13/05/2015.
 */
public class CryptoEngine {

    public KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException

    {
        SecureRandom random = new SecureRandom();

        //Create the initial Key Pair
        KeyPairGenerator generator;
        generator = KeyPairGenerator.getInstance("RSA","BC");
        generator.initialize(1024, random);
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }

    public String encrypt(String plaintext, PublicKey pubKey) throws NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            InvalidKeySpecException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException,
            IOException
    {
        //Open the file into a byte array
        byte [] input = plaintext.getBytes();

        //Generate a random seed for the encryption
        //and do the actual encryption
        SecureRandom seed = new SecureRandom();
        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, seed);
        byte[] rawCipherText = cipher.doFinal(input);

        String cipherText = new String(rawCipherText);

        return cipherText;
    }

    public String decrypt(String cipherText, PrivateKey privateKey) throws	UnrecoverableKeyException,
            KeyStoreException,
            NoSuchAlgorithmException,
            IOException,
            NoSuchProviderException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException
    {
        //Open the file into a byte array
        byte [] input = cipherText.getBytes();

        //Do the actual decryption
        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] rawPlainText = cipher.doFinal(input);
        String plainText = new String(rawPlainText);

        return plainText;
    }

}
