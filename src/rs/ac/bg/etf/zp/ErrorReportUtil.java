package rs.ac.bg.etf.zp;

public class ErrorReportUtil {
	
	public static void reportError(Exception e) {
		System.err.println(e.toString());
	}

	public static void reportError(String message) {
		System.err.println(message);
	}

}
