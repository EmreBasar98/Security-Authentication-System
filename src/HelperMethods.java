import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
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

public class HelperMethods {
    public static String byteToB64(final byte[] hash) {
        return Base64.getEncoder().encodeToString(hash);
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

    public static byte[] encrypt(String msg)
            throws CertificateException, FileNotFoundException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PublicKey publicKey = CertificateFactory.getInstance("X.509")
                .generateCertificate(new FileInputStream("cert/KDC")).getPublicKey();

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

    public static String decrypt(byte[] ciphertext)
            throws CertificateException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidKeySpecException, IOException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, getKDCPrivateKey());
        return new String(cipher.doFinal(ciphertext));

    }

    private static PrivateKey getKDCPrivateKey() throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        BufferedReader bReader = new BufferedReader(new FileReader("keys/KDC"));
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
}
