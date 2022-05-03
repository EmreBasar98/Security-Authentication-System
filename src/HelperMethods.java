import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

public class HelperMethods {
    public static String byteToB64(final byte[] hash) {
        return Base64.getEncoder().encodeToString(hash);
    }

    public static String now() {
        return new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Date());
    }

    public static void log(String p, String msg) {
        try {
            FileWriter myWriter = new FileWriter(p);
            myWriter.write(msg);
            myWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
