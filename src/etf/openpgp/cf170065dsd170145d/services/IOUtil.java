package etf.openpgp.cf170065dsd170145d.services;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;


/**
 * 
 * Utility class for IO operations
 * 
 * 
 * @author Filip Carevic
 *
 */
public class IOUtil {
	
	/**
	 * @param filename
	 * @param data
	 * @throws IOException
	 */
	public static void writeToFile(String filename, byte[] data) throws IOException {
		OutputStream outputStream;
			outputStream = new FileOutputStream(filename);
			outputStream.write(data);
			outputStream.close();
	
	}
	
	/**
	 * 
	 * @param filename
	 * @return
	 * @throws IOException
	 */
	
	public static byte[] readFromFile(String filename) throws IOException {
	    FileInputStream fileInputStream = new FileInputStream(filename);
	    byte[] bytes= fileInputStream.readAllBytes();
	    fileInputStream.close();
	    return bytes;
	}
	

}
