import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Formatter;
import java.util.Random;
import java.util.regex.Pattern;

public class KDC {
    //TO-DO : logda üzerine yazıyor, append halinde yapılacak
    private final String MAILSERVER_ID = "Mail";
    private final String WEBSERVER_ID  = "Web";
    private final String DBSERVER_ID   = "Database";
    private final String CLIENT_ID     = "Alice";
    private final String KDC_ID        = "KDC";

    public KDC() throws Exception {
        createLogFile();
        createPassword();

        ServerSocket sersock = new ServerSocket(3000);
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
        while (true) {
            receiveMessage = receiveRead.readLine();
            String pw = extractPW(receiveMessage);

            while (!verifyPassword(pw)) {
                String msgDirect = KDC_ID +"->"+ CLIENT_ID;
                String logline = HelperMethods.now()+" " +msgDirect+" : "+"Password Denied";
                HelperMethods.log("KDC_Log.txt", logline);
                sendMessage = "Password Denied";
                pwrite.println(sendMessage);
                pw = receiveRead.readLine();
            }

            System.out.println("PW verified");
            sendMessage = "PW verified";
            pwrite.println(sendMessage);
            pwrite.flush();
        }
    }

    public static void main(String[] args) throws Exception {
        new KDC();
    }

    private void createLogFile() throws IOException {
        String p = "KDC_Log.txt";
        File f = new File(p);
        if (!f.exists()) {
            f.createNewFile();
        }
    }

    private void createPassword() {
        String SALTCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        StringBuilder salt = new StringBuilder();
        Random rnd = new Random();
        while (salt.length() < 18) { // length of the random string.
            int index = (int) (rnd.nextFloat() * SALTCHARS.length());
            salt.append(SALTCHARS.charAt(index));
        }

        String plainPW = salt.toString();
        String encPW = encryptPassword(plainPW);
        String ts1 = HelperMethods.now();
        String logLine = ts1 + " " + plainPW;
        HelperMethods.log("KDC_Log.txt", logLine);
        HelperMethods.log("passwd", encPW);
    }

    private String encryptPassword(String password) {
        String sha1 = "";
        try {
            MessageDigest crypt = MessageDigest.getInstance("SHA-1");
            crypt.reset();
            crypt.update(password.getBytes("UTF-8"));
            sha1 = HelperMethods.byteToB64(crypt.digest());
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return sha1;
    }

    private String extractPW(String clMessage) {
        String pw = null;
        if(clMessage.contains("Web")) {
            pw = clMessage.split("Web")[1];
        }
        else if(clMessage.contains("Database")){
            pw = clMessage.split("Database")[1];
        }
        else if(clMessage.contains("Mail")){
            pw = clMessage.split("Mail")[1];
        }
        return pw;
    }

    private boolean verifyPassword(String password) throws IOException {
        BufferedReader bReader = new BufferedReader(new FileReader("KDC_Log.txt"));
        String firstLine = bReader.readLine();
        String plainPW = firstLine.split(" ")[2];
        System.out.println(plainPW);
        bReader.close();
        return password.equals(plainPW);
    }
}
