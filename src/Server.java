import java.io.*;
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
    public static void run(int serverPort) throws Exception {
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

            String receiveMessage, sendMessage;

            receiveMessage = receiveRead.readLine();
            System.out.println("deneme" + receiveMessage);
            Object[] returnObjects = thirdStepSplitter(receiveMessage);
            String decryptedNonce1 = (String) returnObjects[0];
            SecretKey sessionKey = (SecretKey) returnObjects[1];
            String fourthMessage = prepareFourthStep(decryptedNonce1, HelperMethods.generateNonce(), sessionKey);
            pwrite.println(fourthMessage);
            pwrite.flush();

            receiveMessage = receiveRead.readLine();
            System.out.println(receiveMessage);
            handleFifthMessage(receiveMessage, sessionKey);

        }
    }

    private static Object[] thirdStepSplitter(String msg)
            throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
        String clientID = msg.split(",")[0];
        String encryptedTicketString = msg.split(",")[1];
        String encryptedNonce1String = msg.split(",")[2];
        String decryptedTicketString = HelperMethods.decrypt(HelperMethods.Base64toByte(encryptedTicketString), "Mail");
        System.out.println("encrypted nonce: " + encryptedNonce1String);
        SecretKey sessionKey = HelperMethods.stringToSecretKey(decryptedTicketString.split(",")[3]);
        String decryptedNonce = HelperMethods.decryptNonce(encryptedNonce1String, sessionKey);
        System.out.println("decrypted nonce: " + HelperMethods.decryptNonce(encryptedNonce1String, sessionKey));
        Object[] returnObject = { decryptedNonce, sessionKey };
        return returnObject;
    }

    private static String prepareFourthStep(String nonce1, String nonce2, SecretKey sessionKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException {
        nonce1 = HelperMethods.noncePlusOne(nonce1);
        String msg = String.join(",", nonce1, nonce2);
        String encryptedMsg = HelperMethods.encryptNonce(sessionKey, msg)[0];
        return encryptedMsg;
    }

    private static void handleFifthMessage(String msg, SecretKey sessionKey) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        String decryptedMessage = HelperMethods.decryptNonce(msg, sessionKey);
        System.out.println(decryptedMessage);
    }

}