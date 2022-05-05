import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;

class Client {
    private final String MAILSERVER_ID = "Mail";
    private final String WEBSERVER_ID = "Web";
    private final String DBSERVER_ID = "Database";
    private final String CLIENT_ID = "Alice";
    private final String KDC_ID = "KDC";

    private final String CLIENT_KEY = "keys/Client.key";
    private final String KDC_KEY = "cert/KDC.crt";
    private final String CLIENT_LOG = "log/Client_Log.txt";

    private final int KDC_PORT = 3000;
    private final int MAILSERVER_PORT = 3001;
    private final int WEBSERVER_PORT = 3002;
    private final int DBSERVER_PORT = 3003;

    public Client() throws Exception {
        HashMap<String, Integer> ports = new HashMap<>();
        ports.put(MAILSERVER_ID, MAILSERVER_PORT);
        ports.put(WEBSERVER_ID, WEBSERVER_PORT);
        ports.put(DBSERVER_ID, DBSERVER_PORT);

        while (true) {

            Socket kdcSock = new Socket("127.0.0.1", KDC_PORT);
            // reading from keyboard (keyRead object)
            BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
            // sending to client (pwrite object)
            OutputStream kdc_ostream = kdcSock.getOutputStream();
            PrintWriter kdc_pwrite = new PrintWriter(kdc_ostream, true);

            // receiving from server ( receiveRead object)
            InputStream kdc_istream = kdcSock.getInputStream();
            BufferedReader kdc_receiveRead = new BufferedReader(new InputStreamReader(kdc_istream));

            String receiveMessage, sendMessage;

            String serverId = serverConnection(keyRead);

            System.out.println("Enter password");
            String password = keyRead.readLine();

            kdc_pwrite.println(createMessageToKDC(serverId, password)); // sending to server
            kdc_pwrite.flush(); // flush the data
            String thirdStep = null;
            SecretKey sessionKey = null;
            String nonce1 = null;
            if ((receiveMessage = kdc_receiveRead.readLine()) != null) // receive from server
            {
                // System.out.println(receiveMessage); // displaying at DOS prompt
                while (checkForDeny(receiveMessage)) {
                    System.out.println("Password denied. Please enter password again");
                    password = keyRead.readLine();
                    kdc_pwrite.println(password); // sending to server
                    kdc_pwrite.flush();
                    receiveMessage = kdc_receiveRead.readLine();
                }
                String[] KDCMessageParts = receiveMessage.split(",");
                System.out.println(KDCMessageParts.length);
                String decryptedMessageFirst = HelperMethods.decrypt(HelperMethods.Base64toByte(KDCMessageParts[0]),
                        "Alice");
                String decryptedTicket = HelperMethods.decrypt(HelperMethods.Base64toByte(KDCMessageParts[1]),
                        serverId);
                System.out.println(decryptedMessageFirst);
                System.out.println(decryptedTicket);
                sessionKey = extractSessionKey(decryptedMessageFirst);
                String[] encryptedNonceArray = HelperMethods.encryptNonce(sessionKey, null);
                String encryptedNonce1 = encryptedNonceArray[0];
                nonce1 = encryptedNonceArray[1];
                System.out.println("encrypted nonce: " + encryptedNonce1);
                thirdStep = String.join(",", "Alice", KDCMessageParts[1], encryptedNonce1);

            }

            kdcSock.close();
            kdc_istream.close();
            kdc_ostream.close();

            Socket serverScok = new Socket("127.0.0.1", ports.get(serverId));
            System.out.println(ports.get(serverId));

            // sending to server (pwrite object)
            OutputStream server_ostream = serverScok.getOutputStream();
            PrintWriter server_pwrite = new PrintWriter(server_ostream, true);

            // // receiving from server ( receiveRead object)
            InputStream server_istream = serverScok.getInputStream();
            BufferedReader server_receiveRead = new BufferedReader(new InputStreamReader(server_istream));

            server_pwrite.println(thirdStep);
            server_pwrite.flush();

            receiveMessage = server_receiveRead.readLine();
            String nonce2 = handleFourthMessage(receiveMessage, sessionKey, nonce1);
            System.out.println(receiveMessage);

            String fifthMessage = prepareFifthMessage(nonce2, sessionKey);
            server_pwrite.println(fifthMessage);
            server_pwrite.flush();
        }

    }

    private String serverConnection(BufferedReader keyRead) throws IOException {
        String serverID = null;
        boolean isValid = false;
        while (!isValid) {
            System.out.println("Enter a server name to connect " +
                    "(\"" + MAILSERVER_ID + "\"|\"" + WEBSERVER_ID + "\"|\"" + DBSERVER_ID + "\"): ");

            serverID = keyRead.readLine();

            if ((serverID.equalsIgnoreCase(MAILSERVER_ID) ||
                    serverID.equalsIgnoreCase(WEBSERVER_ID) ||
                    serverID.equalsIgnoreCase(DBSERVER_ID)))
                isValid = true;
            else
                System.out.println("Please enter one of the options...");
        }
        serverID = serverID.toLowerCase();
        serverID = serverID.substring(0, 1).toUpperCase() + serverID.substring(1);
        return serverID;
    }

    private String createMessageToKDC(String serverID, String pw)
            throws InvalidKeyException, CertificateException, FileNotFoundException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        String msgToEncrypted = String.join(",", "Alice", pw, serverID, HelperMethods.now());
        byte[] encryptedMsg = HelperMethods.encrypt(msgToEncrypted, "KDC");
        String lastMsg = String.join(",", "Alice", HelperMethods.byteToB64(encryptedMsg));
        return lastMsg;
    }

    private boolean checkForDeny(String rm) {
        return rm.equals("Password Denied");
    }

    public static void main(String[] args) {
        System.out.println("Client is on!");
        try {
            new Client();
        } catch (ConnectException ce) {
            System.out.println("Server is not available!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private SecretKey extractSessionKey(String msg) {
        String sessionKey = msg.split(",")[0];
        return HelperMethods.stringToSecretKey(sessionKey);
    }

    private String handleFourthMessage(String msg, SecretKey sessionKey, String oldNonce1) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        String decryptedMessage = HelperMethods.decryptNonce(msg, sessionKey);
        System.out.println(decryptedMessage);
        String nonce1 = decryptedMessage.split(",")[0];
        String nonce2 = decryptedMessage.split(",")[1];
        BigInteger nonce1NewBigInt = new BigInteger(nonce1);
        BigInteger nonce1OldBigInt = new BigInteger(oldNonce1);
        if (!(nonce1NewBigInt.subtract(nonce1OldBigInt).equals(new BigInteger("1")))) {
            System.out.println("Authentication is failed!");
            System.exit(1);
        }
        return nonce2;
    }

    private String prepareFifthMessage(String nonce2, SecretKey sessionKey) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("original nonce2: " + nonce2);
        nonce2 = HelperMethods.noncePlusOne(nonce2);
        System.out.println("nonce2: " + nonce2);
        return HelperMethods.encryptNonce(sessionKey, nonce2)[0];
    }

}