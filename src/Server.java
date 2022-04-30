import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

    public Server(int port) {
        try {
            ServerSocket server = new ServerSocket(port);
            System.out.println("Server started::");

            System.out.println("Waiting for a client ........");

            //initialize socket and input stream
            Socket socket = server.accept();
            System.out.println("Client accepted.");

            // takes input from the client socket
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));

            String line = "";

            // reads message from client until "Done" is sent
            while (!line.equals("Done")) {
                try {
                    line = in.readUTF();
                    System.out.println(line);

                } catch (IOException i) {
                    System.out.println(i);
                }
            }
            System.out.println("Closing connection");

            // close connection
            socket.close();
            in.close();
        } catch (IOException i) {
            System.out.println(i);
        }
    }

    public static void main(String args[]) {
        Server serverSideProgram = new Server(5000);
    }

}