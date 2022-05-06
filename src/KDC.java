import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Formatter;
import java.util.Random;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;
import sun.security.tools.keytool.Main;

public class KDC {
    // TO-DO : logda üzerine yazıyor, append halinde yapılacak
    private final String MAILSERVER_ID = "Mail";
    private final String WEBSERVER_ID = "Web";
    private final String DBSERVER_ID = "Database";
    private final String CLIENT_ID = "Alice";
    private final String KDC_ID = "KDC";
    private final String[] dirs = { "cert", "keys", "keyPairs" };
    private final String[] keyHolders = { "KDC", "Alice", "Web", "Database", "Mail" };

    public KDC() throws Exception {
        createLogFile();
        createPassword();
        HelperMethods.createDirectories(dirs);
        createKeyPairs(keyHolders);

        while (true) {

            ServerSocket sersock = new ServerSocket(3000);
            Socket sock = sersock.accept();
            // reading from keyboard (keyRead object)
            BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
            // sending to client (pwrite object)
            OutputStream ostream = sock.getOutputStream();
            PrintWriter pwrite = new PrintWriter(ostream, true);

            // receiving from server ( receiveRead object)
            InputStream istream = sock.getInputStream();
            BufferedReader receiveRead = new BufferedReader(new InputStreamReader(istream));

            String receiveMessage, sendMessage;
            receiveMessage = receiveRead.readLine();
            System.out.println("--------");
            System.out.println(receiveMessage);
            System.out.println("--------");
            byte[] decodedString = Base64.getDecoder().decode(receiveMessage.split(",")[1]);
            String logLine1 = HelperMethods.now() + " Alice->KDC : " + receiveMessage;
            HelperMethods.log("KDC_Log.txt", logLine1);
            String decryptedMessage = HelperMethods.decrypt(decodedString, "KDC");
            String logLine2 = HelperMethods.now() + " Message Decrypted : " + decryptedMessage;
            HelperMethods.log("KDC_Log.txt", logLine2);
            String pw = extractPW(decryptedMessage);

            while (!verifyPassword(pw)) {
                String msgDirect = KDC_ID + "->" + CLIENT_ID;
                String logline = HelperMethods.now() + " " + msgDirect + " : " + "Password Denied";
                HelperMethods.log("KDC_Log.txt", logline);
                sendMessage = "Password Denied";
                pwrite.println(sendMessage);
                pw = receiveRead.readLine();
            }

            System.out.println("PW verified");
            String msgDirect = KDC_ID + "->" + CLIENT_ID;
            String logline = HelperMethods.now() + " " + msgDirect + " : " + "Password Verified";
            HelperMethods.log("KDC_Log.txt", logline);
            sendMessage = messageToClient(extractServerID(HelperMethods.decrypt(decodedString, "KDC")));

            pwrite.println(sendMessage);
            pwrite.flush();

            sersock.close();
            ostream.close();
            istream.close();
        }
    }

    public static void main(String[] args) throws Exception {
        new KDC();
    }

    private void createLogFile() throws IOException {
        String p = "KDC_Log.txt";
        File f = new File(p);
        if (!f.exists()) {
            f.createNewFile();
        }
    }

    private void createPassword() {
        String SALTCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        StringBuilder salt = new StringBuilder();
        Random rnd = new Random();
        while (salt.length() < 18) { // length of the random string.
            int index = (int) (rnd.nextFloat() * SALTCHARS.length());
            salt.append(SALTCHARS.charAt(index));
        }

        String plainPW = salt.toString();
        String encPW = encryptPassword(plainPW);
        String ts1 = HelperMethods.now();
        String logLine = ts1 + " " + plainPW;
        HelperMethods.log("KDC_Log.txt", logLine);
        HelperMethods.log("passwd", encPW);
    }

    private String encryptPassword(String password) {
        String sha1 = "";
        try {
            MessageDigest crypt = MessageDigest.getInstance("SHA-1");
            crypt.reset();
            crypt.update(password.getBytes("UTF-8"));
            sha1 = HelperMethods.byteToB64(crypt.digest());
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return sha1;
    }

    private String extractPW(String clMessage) {
        System.out.println("First Message From Client : " + clMessage);
        return clMessage.split(",")[1];
    }

    private String extractServerID(String clMessage) {
        return clMessage.split(",")[2];
    }

    private boolean verifyPassword(String password) throws IOException {
        BufferedReader passwd = new BufferedReader(new FileReader("passwd"));

        String lastLine = "";
        String sCurrentLine;
        while ((sCurrentLine = passwd.readLine()) != null) {
            lastLine = sCurrentLine;
        }

        passwd.close();
        return lastLine.equals(encryptPassword(password));
    }

    private void createKeyPairs(String[] keyHolders) throws NoSuchAlgorithmException, InvalidKeyException,
            KeyStoreException, CertificateException, NoSuchProviderException, SignatureException, IOException {

        for (String keyHolder : keyHolders) {
            CertAndKeyGen certAndKeyGen = new CertAndKeyGen("RSA", "SHA256withRSA");
            certAndKeyGen.generate(2048);
            // if (keyHolder.equals("KDC")) {
            // // System.out.println(certAndKeyGen.getPrivateKey().getEncoded());
            // //
            // System.out.println(Arrays.toString(certAndKeyGen.getPublicKey().getEncoded()));
            // }
            Path path = Paths.get("keys/" + keyHolder);
            if (!Files.exists(path)) {
                FileWriter myWriter = new FileWriter("keys/" + keyHolder);
                myWriter.write(HelperMethods.byteToB64(certAndKeyGen.getPrivateKey().getEncoded()));
                myWriter.close();
            }

            generate(certAndKeyGen, keyHolder);
            generateCertificate(keyHolder);
        }
    }

    public void generate(CertAndKeyGen keypair, String keyStoreName)
            throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, NoSuchProviderException,
            InvalidKeyException, SignatureException {
        // Method to create a keystore for created keypair. This keypair file is going o
        // be used later for certificate creation.
        char[] psw = "password".toCharArray();
        OutputStream fout = null;
        if (!new File("keyPairs/" + keyStoreName).exists()) {
            try {

                fout = new java.io.FileOutputStream("keyPairs/" + keyStoreName);

                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(null, psw);

                X500Name x500Name = new X500Name("CN=EMRE");

                PrivateKey privateKey = keypair.getPrivateKey();

                X509Certificate[] chain = new X509Certificate[1];
                chain[0] = keypair.getSelfCertificate(x500Name, 35000 * 24L * 60L * 60L);
                // stroing the key pair in keystore
                keyStore.setKeyEntry("keypair", privateKey, "password".toCharArray(), chain);
                keyStore.store(fout, psw);
            } finally {
                if (fout != null) {
                    fout.close();
                }
            }
        }

    }

    private void generateCertificate(String keyHolder) throws IOException {
        // Generating a request for certificate signing using keytool
        if (!new File("cert/" + keyHolder).exists()) {
            execute(" -certreq" +
                    " -alias keypair" +
                    " -dname CN=EMRE" +
                    " -storetype PKCS12" +
                    " -file request" + keyHolder + ".csr" +
                    " -storepass password" +
                    " -keystore " + "keyPairs/" + keyHolder +
                    " -sigalg SHA256withRSA");

            // Generating X.509 public certificate with generated request
            execute(" -gencert" +
                    " -validity 365" +
                    " -keystore " + "keyPairs/KDC" +
                    " -alias keypair" +
                    " -storetype PKCS12" +
                    " -infile request" + keyHolder + ".csr" +
                    " -storepass password" +
                    " -sigalg SHA256withRSA" +
                    " -outfile " + "cert/" + keyHolder);

            // Deleting keypair and request files for not letting them conflict with further
            // runs.

            // Files.deleteIfExists(FileSystems.getDefault().getPath("keyPairs/" +
            // keyHolder));
            Files.deleteIfExists(FileSystems.getDefault().getPath("request" + keyHolder + ".csr"));
        }

    }

    private void execute(String command) {
        // en executer for keytool
        try {
            Main.main(command.trim().split("\\s+"));
        } catch (Exception e) {
            System.out.println("ERROR, keytool command could not be executed!");
        }
    }

    private String messageToClient(String serverID)
            throws NoSuchAlgorithmException, InvalidKeyException, CertificateException, FileNotFoundException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        String sessionKey = createSessionKey();
        String ts2 = HelperMethods.now();
        String messageToEncrypt = String.join(",", sessionKey, serverID, ts2);
        String logLine1 = ts2 + " KDC->Alice : " + messageToEncrypt;

        byte[] encryptedMessage = HelperMethods.encrypt(messageToEncrypt, "Alice");
        byte[] ticket = HelperMethods.encrypt(String.join(",", "Alice", serverID, ts2, sessionKey), serverID);
        String message = String.join(",", HelperMethods.byteToB64(encryptedMessage), HelperMethods.byteToB64(ticket));
        String logLine2 = ts2 + " KDC->Alice : " + message;
        HelperMethods.log("KDC_Log.txt", logLine1);
        HelperMethods.log("KDC_Log.txt", logLine2);
        System.out.println("Send to Client : " + message);
        return message;
    }

    private String createSessionKey() throws NoSuchAlgorithmException {
        KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
        // Initializing the KeyGenerator
        keygenerator.init(256, new SecureRandom());
        // Generating a key
        SecretKey key = keygenerator.generateKey();
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // private void dneme(SecretKey sessionKey) throws NoSuchAlgorithmException,
    // NoSuchPaddingException,
    // InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    // Cipher cipher = Cipher.getInstance("AES");
    // cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
    // byte[] input = "numan".getBytes();
    // cipher.update(input);
    // byte[] cipherText = cipher.doFinal();
    //
    // Cipher cipher2 = Cipher.getInstance("AES");
    // cipher2.init(Cipher.DECRYPT_MODE, sessionKey);
    // System.out.println(new String(cipher.doFinal(cipherText)));
    // }

    // private byte[] encrypt()
    // throws CertificateException, FileNotFoundException, NoSuchAlgorithmException,
    // NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
    // BadPaddingException {
    // PublicKey publicKey = CertificateFactory.getInstance("X.509")
    // .generateCertificate(new FileInputStream("cert/KDC")).getPublicKey();

    // System.out.println("---------------");
    // System.out.println(Arrays.toString(publicKey.getEncoded()));
    // Cipher cipher = Cipher.getInstance("RSA");
    // cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    // byte[] input = "Welcome to Tutorialspoint".getBytes();
    // cipher.update(input);
    // byte[] cipherText = cipher.doFinal();
    // System.out.println(cipherText);
    // return cipherText;
    // }

    // private void decrypt(byte[] ciphertext)
    // throws CertificateException, NoSuchAlgorithmException,
    // NoSuchPaddingException, InvalidKeyException,
    // InvalidKeySpecException, IOException, IllegalBlockSizeException,
    // BadPaddingException {
    // Cipher cipher = Cipher.getInstance("RSA");
    // System.out.println("......");
    // cipher.init(Cipher.DECRYPT_MODE, getKDCPrivateKey());
    // System.out.println("-------");
    // System.out.println(new String(cipher.doFinal(ciphertext)));

    // }

    // public PrivateKey getPrivateKey(byte[] privateKeyInfo) throws
    // NoSuchAlgorithmException, InvalidKeySpecException {
    // // getting the private key from given byte array

    // KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    // PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyInfo);

    // return keyFactory.generatePrivate(privateKeySpec);
    // }

    // private String signature(StringBuilder certificate, String hashType)
    // throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
    // SignatureException,
    // CertificateException, IOException, InvalidKeySpecException {
    // String hash = "SHA256";

    // byte[] data = certificate.toString().getBytes(StandardCharsets.UTF_8);

    // Signature signature = Signature.getInstance(hash + "withRSA");
    // signature.initSign(getKDCPrivateKey());
    // signature.update(data);
    // byte[] signatureBytes = signature.sign();

    // return Base64.getEncoder().encodeToString(signatureBytes);
    // }

    // private PrivateKey getKDCPrivateKey() throws IOException,
    // NoSuchAlgorithmException, InvalidKeySpecException {
    // BufferedReader bReader = new BufferedReader(new FileReader("keys/KDC"));
    // String firstLine = bReader.readLine();
    // bReader.close();
    // byte[] privateKeyInfo = Base64.getDecoder().decode(firstLine);
    // PrivateKey privateKey = getPrivateKey(privateKeyInfo);
    // System.out.println("getKDC");
    // // System.out.println(Arrays.toString(privateKey.getEncoded()));
    // return privateKey;
    // }

}
