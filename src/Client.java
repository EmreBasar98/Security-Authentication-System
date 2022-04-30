import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;

public class Client {

    //here we simply initialize socket, input & output streams

    private static BufferedReader input=null;

    //parametrized constructor for CilentSideProgram
    public Client(String address, Integer port) {

        //code to establish a connection
        Socket socket = null;
        DataOutputStream output = null;
        try {
            socket = new Socket(address, port);
            input = new BufferedReader(new InputStreamReader(System.in));

            // sends output to the socket
            output = new DataOutputStream(socket.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }

        String line = "";
        //below line is to read message from input
        while (!(line.equals("Done"))) {
            try {
                line = input.readLine();
                assert output != null;
                output.writeUTF(line);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        try {
            input.close();
            output.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static void main(String[] args) {
        Client clientProgram = new Client("127.0.0.1", 5000);
    }
}