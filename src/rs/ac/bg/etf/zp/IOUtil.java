package rs.ac.bg.etf.zp;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class IOUtil {
	public static void writeToFile(String filename, byte[] data) throws IOException {
		OutputStream outputStream;
			outputStream = new FileOutputStream(filename);
			outputStream.write(data);
	
	}
	
	public static byte[] readFromFile(String filename) throws IOException {
	    FileInputStream fileInputStream = new FileInputStream(filename);
	    return fileInputStream.readAllBytes();
	}
	

}
