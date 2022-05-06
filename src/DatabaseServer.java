import java.net.SocketException;

public class DatabaseServer {
    private static final String DATABASE_LOG = "Database_Log.txt";
    private static final String DATABASE_KEY = "Database.key";
    
    private static final int DATABASE_PORT = 3003;

    public static void main(String[] args) throws Exception {
        System.out.println("Database server is on!");
        try{Server.run(DATABASE_PORT, "Database");}
        catch(SocketException e) {System.out.println("Client has lost the connection...");}
    }
}
