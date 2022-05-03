import javax.crypto.BadPaddingException;
import java.io.*;
import java.net.*;
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

            // receiving from server ( receiveRead  object)
            InputStream kdc_istream = kdcSock.getInputStream();
            BufferedReader kdc_receiveRead = new BufferedReader(new InputStreamReader(kdc_istream));


            String receiveMessage, sendMessage;
            
            String serverId = serverConnection(keyRead);

            System.out.println("Enter password");
            String password = keyRead.readLine();

            kdc_pwrite.println(createMessage(serverId, password));       // sending to server
            kdc_pwrite.flush();                    // flush the data
            if ((receiveMessage = kdc_receiveRead.readLine()) != null) //receive from server
            {
                System.out.println(receiveMessage); // displaying at DOS prompt
                while (checkForDeny(receiveMessage)){
                    System.out.println("Password denied. Please enter password again");
                    password = keyRead.readLine();
                    kdc_pwrite.println(password);       // sending to server
                    kdc_pwrite.flush();
                    receiveMessage = kdc_receiveRead.readLine();
                }
            }

            kdcSock.close();
            kdc_istream.close();
            kdc_ostream.close();

            Socket serverScok = new Socket("127.0.0.1", ports.get(serverId));
            System.out.println(ports.get(serverId));

            // sending to server (pwrite object)
            OutputStream server_ostream = serverScok.getOutputStream();
            PrintWriter server_pwrite = new PrintWriter(server_ostream, true);

            // // receiving from server ( receiveRead  object)
            InputStream server_istream = serverScok.getInputStream();
            BufferedReader server_receiveRead = new BufferedReader(new InputStreamReader(server_istream));

            String nonce1 = "5";
            server_pwrite.println(CLIENT_ID+nonce1);
            server_pwrite.flush();

            receiveMessage = server_receiveRead.readLine();
            System.out.println(receiveMessage);

            
            server_pwrite.println("gelennonce2");
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
            else System.out.println("Please enter one of the options...");
        }
        serverID = serverID.toLowerCase();
        serverID = serverID.substring(0, 1).toUpperCase() + serverID.substring(1);
        return serverID;
    }

    private String createMessage(String serverID, String pw) {
        String msg = serverID+pw;
        return msg;
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
}