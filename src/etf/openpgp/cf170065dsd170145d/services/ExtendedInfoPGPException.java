/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.cf170065dsd170145d.services;

/**
 * Exception class
 *
 * @author Filip Carevic
 */
public class ExtendedInfoPGPException extends Exception {

    /**
     *
     */
    public ExtendedInfoPGPException() {
    }

    /**
     *
     * @param message
     */
    public ExtendedInfoPGPException(String message) {
        super(message);
    }

    /**
     *
     * @param message
     * @param cause
     */
    public ExtendedInfoPGPException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     *
     * @param cause
     */
    public ExtendedInfoPGPException(Throwable cause) {
        super(cause);
    }

    /**
     *
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace
     */
    public ExtendedInfoPGPException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
