package etf.openpgp.cf170065dsd170145d.services;

import java.io.IOException;

/**
 * Error reporting util
 *
 * @author Filip Carevic
 *
 */
public class ErrorReportUtil {

    /**
     * Print error to std
     *
     * @param e
     */
    public static void reportError(Exception e) {
        System.err.println(e.toString());
        e.printStackTrace();
    }

    /**
     * prints error to std
     *
     * @param message
     */
    public static void reportError(String message) {
        System.err.println(message);
    }

    /**
     * Prints error and writes data to file
     *
     * @param e
     * @param filename
     * @param data
     */
    public static void reportAndWriteToFile(Exception e, String filename, byte[] data) {
        reportError(e);
        try {
            IOUtil.writeToFile(filename, data);
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            ErrorReportUtil.reportError(e);

        }
    }

}
