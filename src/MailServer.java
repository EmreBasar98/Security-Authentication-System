import java.net.SocketException;

public class MailServer {

    private static final String MAIL_LOG = "Mail_Log.txt";
    private static final String MAIL_KEY = "Mail.key";
    
    private static final int MAIL_PORT = 3001;

    public static void main(String[] args) throws Exception {
        System.out.println("Mail server is on!");
        try{Server.run(MAIL_PORT);}
        catch(SocketException e) {System.out.println("Client has lost the connection...");}
    }
}
