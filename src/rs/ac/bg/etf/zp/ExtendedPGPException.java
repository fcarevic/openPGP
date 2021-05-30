/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rs.ac.bg.etf.zp;

/**
 *
 * @author CAR
 */
public class ExtendedPGPException extends Exception {

    public ExtendedPGPException() {
    }

    public ExtendedPGPException(String message) {
        super(message);
    }

    public ExtendedPGPException(String message, Throwable cause) {
        super(message, cause);
    }

    public ExtendedPGPException(Throwable cause) {
        super(cause);
    }

    public ExtendedPGPException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
    
    
}
