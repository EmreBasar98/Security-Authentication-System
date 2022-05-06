import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class Server {
    public static void run(int serverPort, String serverID) throws Exception {
        ServerSocket sersock = new ServerSocket(serverPort);
        while (true) {
            Socket sock = sersock.accept();
            // reading from keyboard (keyRead object)
            BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
            // sending to client (pwrite object)
            OutputStream ostream = sock.getOutputStream();
            PrintWriter pwrite = new PrintWriter(ostream, true);

            // receiving from server ( receiveRead object)
            InputStream istream = sock.getInputStream();
            BufferedReader receiveRead = new BufferedReader(new InputStreamReader(istream));

            // recieving the third message from client
            String receiveMessage;

            receiveMessage = receiveRead.readLine();
            HelperMethods.log(serverID + "_Log.txt",
                    HelperMethods.now() + " Alice->" + serverID + " : " + receiveMessage);
            Object[] returnObjects = thirdStepSplitter(receiveMessage, serverID);

            // getting nonce1 and session key from message
            String decryptedNonce1 = (String) returnObjects[0];
            SecretKey sessionKey = (SecretKey) returnObjects[1];

            // prepare and send fouth message
            String nonce2 = HelperMethods.generateNonce();
            String fourthMessage = prepareFourthStep(decryptedNonce1, nonce2, sessionKey,
                    serverID);
            pwrite.println(fourthMessage);
            pwrite.flush();

            // recieve fifth message
            receiveMessage = receiveRead.readLine();
            System.out.println(receiveMessage);
            handleFifthMessage(receiveMessage, sessionKey, nonce2, serverID);

        }
    }

    private static Object[] thirdStepSplitter(String msg, String serverID)
            throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
        String clientID = msg.split(",")[0];
        String encryptedTicketString = msg.split(",")[1];
        String encryptedNonce1String = msg.split(",")[2];
        String decryptedTicketString = HelperMethods.decrypt(HelperMethods.Base64toByte(encryptedTicketString),
                serverID);
        SecretKey sessionKey = HelperMethods.stringToSecretKey(decryptedTicketString.split(",")[3]);
        String decryptedNonce = HelperMethods.decryptNonce(encryptedNonce1String, sessionKey);
        System.out.println("Nonce1 : " + decryptedNonce);
        Object[] returnObject = { decryptedNonce, sessionKey };
        System.out.println("Third Message : " + msg);
        String timestamp = HelperMethods.now();

        HelperMethods.log(serverID + "_Log.txt", timestamp + " Ticket Decrypted : " + decryptedTicketString);
        HelperMethods.log(serverID + "_Log.txt", timestamp + " Message Decrypted : N1=" + decryptedNonce);
        return returnObject;
    }

    private static String prepareFourthStep(String nonce1, String nonce2, SecretKey sessionKey, String serverID)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException {
        nonce1 = HelperMethods.noncePlusOne(nonce1);
        String msg = String.join(",", nonce1, nonce2);
        System.out.println("Fourth message : " + msg);
        String timestamp = HelperMethods.now();
        HelperMethods.log(serverID + "_Log.txt", timestamp + " " + serverID + "->Alice : " + msg);
        String encryptedMsg = HelperMethods.encryptNonce(sessionKey, msg)[0];
        HelperMethods.log(serverID + "_Log.txt", timestamp + " " + serverID + "->Alice : " + encryptedMsg);
        return encryptedMsg;
    }

    private static void handleFifthMessage(String msg, SecretKey sessionKey, String oldNonce2, String serverID)
            throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        String decryptedMessage = HelperMethods.decryptNonce(msg, sessionKey);
        System.out.println("Fifth message : " + decryptedMessage);
        BigInteger newNonce = new BigInteger(decryptedMessage);
        if (!(newNonce.subtract(new BigInteger(oldNonce2)).equals(new BigInteger("1")))) {
            System.out.println("Authentication is failed!");
            System.exit(1);
        }
        HelperMethods.log(serverID + "_Log.txt",
                HelperMethods.now() + " " + serverID + "->Alice : Authenticaion is Completed!");

    }

}