import java.net.SocketException;

public class WebServer {
    private static final String WEB_LOG = "Web_Log.txt";
    private static final String WEB_KEY = "Web.key";
    
    private static final int WEB_PORT = 3002;

    public static void main(String[] args) throws Exception {
        System.out.println("Web server is on!");
        try{Server.run(WEB_PORT, "Web");}
        catch(SocketException e) {System.out.println("Client has lost the connection...");}
    }
}
