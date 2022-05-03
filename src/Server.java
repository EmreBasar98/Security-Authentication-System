import java.io.*;
import java.net.*;

public class Server {
    public static void run(int serverPort) throws Exception {
        ServerSocket sersock = new ServerSocket(serverPort);
        while(true) {
            Socket sock = sersock.accept();
            // reading from keyboard (keyRead object)
            BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
            // sending to client (pwrite object)
            OutputStream ostream = sock.getOutputStream();
            PrintWriter pwrite = new PrintWriter(ostream, true);

            // receiving from server ( receiveRead  object)
            InputStream istream = sock.getInputStream();
            BufferedReader receiveRead = new BufferedReader(new InputStreamReader(istream));

            String receiveMessage, sendMessage;
            
            receiveMessage = receiveRead.readLine();
            System.out.println(receiveMessage);
            
            String nonce2 = "10";
            sendMessage = "gelennonce"+nonce2;
            pwrite.println(sendMessage);
            pwrite.flush();

            receiveMessage = receiveRead.readLine();
            System.out.println(receiveMessage);
        }
    }
}