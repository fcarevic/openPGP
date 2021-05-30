package rs.ac.bg.etf.zp;

import java.io.IOException;

public class ErrorReportUtil {
	
	public static void reportError(Exception e) {
		System.err.println(e.toString());
	}

	public static void reportError(String message) {
		System.err.println(message);
	}
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
