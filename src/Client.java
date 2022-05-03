import javax.crypto.BadPaddingException;
import java.io.*;
import java.net.*;
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

    public Client() throws Exception {
        while (true) {

            Socket sock = new Socket("127.0.0.1", 3000);
            // reading from keyboard (keyRead object)
            BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
            // sending to client (pwrite object)
            OutputStream ostream = sock.getOutputStream();
            PrintWriter pwrite = new PrintWriter(ostream, true);

            // receiving from server ( receiveRead  object)
            InputStream istream = sock.getInputStream();
            BufferedReader receiveRead = new BufferedReader(new InputStreamReader(istream));


            String receiveMessage, sendMessage;
            while (true) {

                String serverId = serverConnection(keyRead);

                System.out.println("Enter password");
                String password = keyRead.readLine();

                pwrite.println(serverId+password);       // sending to server
                pwrite.flush();                    // flush the data
                if ((receiveMessage = receiveRead.readLine()) != null) //receive from server
                {
                    System.out.println(receiveMessage); // displaying at DOS prompt
                }
            }
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