package com.venus.util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Handles AES encryption/decryption of passwords.
 */
public class PasswordUtil {

    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 16;

    private static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }
    private static SecretKey getAESKeyFromPassword(char[] password, byte[] salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } catch (Exception e) {
            Logger.getLogger(PasswordUtil.class.getName()).log(Level.SEVERE, null, e);
            return null;
        }
    }

    /**
     * Encrypts a plain password using the username as a salt base.
     */
    public static String encrypt(String username, String password) {
        try {
            byte[] salt = getRandomNonce(SALT_LENGTH_BYTE);
            byte[] iv = getRandomNonce(IV_LENGTH_BYTE);
            SecretKey key = getAESKeyFromPassword(username.toCharArray(), salt);

            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            byte[] cipherText = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));

            byte[] encrypted = ByteBuffer.allocate(iv.length + salt.length + cipherText.length)
                    .put(iv).put(salt).put(cipherText).array();

            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            Logger.getLogger(PasswordUtil.class.getName()).log(Level.SEVERE, null, e);
            return null;
        }
    }

    /**
     * Decrypts an encrypted password using the username as the salt base.
     */
    public static String decrypt(String encryptedPassword, String username) {
        try {
            byte[] decode = Base64.getDecoder().decode(encryptedPassword);
            ByteBuffer buffer = ByteBuffer.wrap(decode);

            byte[] iv = new byte[IV_LENGTH_BYTE];
            buffer.get(iv);
            byte[] salt = new byte[SALT_LENGTH_BYTE];
            buffer.get(salt);
            byte[] cipherText = new byte[buffer.remaining()];
            buffer.get(cipherText);

            SecretKey key = getAESKeyFromPassword(username.toCharArray(), salt);

            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            byte[] plainText = cipher.doFinal(cipherText);

            return new String(plainText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Logger.getLogger(PasswordUtil.class.getName()).log(Level.SEVERE, null, e);
            return null;
        }
    }
}

