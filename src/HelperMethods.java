import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class HelperMethods {
    public static String byteToB64(final byte[] hash) {
        return Base64.getEncoder().encodeToString(hash);
    }

    public static byte[] Base64toByte(String cipher) {
        byte[] decodedString = Base64.getDecoder().decode(cipher);
        return decodedString;
    }

    public static String now() {
        return new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Date());
    }

    public static void log(String p, String msg) {
        try {
            FileWriter myWriter = new FileWriter(p, true);
            myWriter.write(msg + System.getProperty("line.separator"));
            myWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void createDirectories(String[] dirs) {
        for (String dir : dirs) {
            File creatingDir = new File(dir);
            creatingDir.mkdir();
        }
    }

    public static byte[] encrypt(String msg, String keyHolder)
            throws CertificateException, FileNotFoundException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PublicKey publicKey = CertificateFactory.getInstance("X.509")
                .generateCertificate(new FileInputStream("cert/" + keyHolder)).getPublicKey();

        // System.out.println("---------------");
        // System.out.println(Arrays.toString(publicKey.getEncoded()));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] input = msg.getBytes();
        cipher.update(input);
        byte[] cipherText = cipher.doFinal();
        // System.out.println(cipherText);
        return cipherText;
    }

    public static String decrypt(byte[] ciphertext, String keyHolder)
            throws CertificateException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidKeySpecException, IOException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(keyHolder));
        return new String(cipher.doFinal(ciphertext));

    }

    private static PrivateKey getPrivateKey(String keyHolder) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        BufferedReader bReader = new BufferedReader(new FileReader("keys/" + keyHolder));
        String firstLine = bReader.readLine();
        bReader.close();
        byte[] privateKeyInfo = Base64.getDecoder().decode(firstLine);
        PrivateKey privateKey = getPrivateKey(privateKeyInfo);
        System.out.println("getKDC");
        // System.out.println(Arrays.toString(privateKey.getEncoded()));
        return privateKey;
    }

    public static PrivateKey getPrivateKey(byte[] privateKeyInfo)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        // getting the private key from given byte array

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyInfo);

        return keyFactory.generatePrivate(privateKeySpec);
    }

    public static SecretKey stringToSecretKey(String stringKey) {
        // decode the base64 encoded string
        byte[] decodedKey = HelperMethods.Base64toByte(stringKey);
        // rebuild key using SecretKeySpec
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        System.out.println("decoded key" + Arrays.toString(originalKey.getEncoded()));
        return originalKey;
    }

    public static String decryptNonce(String nonce, SecretKey sessionKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            InvalidKeyException {
        // SecretKeySpec secretKey = new SecretKeySpec(sessionKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey);
        System.out.println("noncecc" + Arrays.toString((cipher.doFinal(Base64toByte(nonce)))));
        return new String(cipher.doFinal(Base64toByte(nonce)));
    }

    public static String[] encryptNonce(SecretKey sessionKey, String nonceParam)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

        String nonce = nonceParam == null ? generateNonce() : nonceParam;
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] input = nonce.getBytes();
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("btob64 npnce" + cipherText.toString());
        System.out.println("cippher" + Arrays.toString(cipherText));
        String[] returnArray = { HelperMethods.byteToB64(cipherText), nonce };
        return returnArray;
    }

    public static String generateNonce() {
        String digit = "0123456789";

        SecureRandom random = new SecureRandom();
        StringBuilder nonce = new StringBuilder();

        // Specifying length of nonce value randomly in range 50 to 100 characters
        int nonceLength = (int) Math.random() * (100 - 50 + 1) + 50;

        // Producing a random order alphanumeric string as password
        for (int i = 0; i < nonceLength; i++)
            nonce.append(digit.charAt(random.nextInt(digit.length())));
        System.out.println("ournonce" + nonce.toString());
        return nonce.toString();
    }

    public static String noncePlusOne(String nonceValue) {
        BigInteger nonce = new BigInteger(nonceValue);
        System.out.println("-----------------");
        System.out.println("nonceValue" + nonceValue);
        nonce = nonce.add(new BigInteger("1"));
        System.out.println("nonce1" + nonce.toString());
        System.out.println("-----------------");

        return nonce.toString();
    }

    // public static String decryptText(byte[] byteCipherText, SecretKey secKey)
    // throws Exception {
    // // AES defaults to AES/ECB/PKCS5Padding in Java 7
    // Cipher aesCipher = Cipher.getInstance("AES");
    // aesCipher.init(Cipher.DECRYPT_MODE, secKey);
    // byte[] bytePlainText = aesCipher.doFinal(byteCipherText);
    // System.out.println("bytePlainText" + new String(bytePlainText));
    // return new String(bytePlainText);
    // }

}
