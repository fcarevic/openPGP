/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.cf170065dsd170145d.GUI;

import javax.swing.JOptionPane;

/**
 *
 * @author Dušan Stijović
 */
public class GUIUtil {

    /**
     *
     * @param email string that is checking
     * @return true if email format is valid
     */
    public static boolean checkEmail(String email) {
        return true;
    }

    /**
     * Show error dialog with specified message
     *
     * @param message
     */
    public static void showErrorMessage(String message) {
        JOptionPane.showMessageDialog(null, message,
                "Error", JOptionPane.ERROR_MESSAGE);
    }

    /**
     * Show info dialog with message
     *
     * @param message
     */
    public static void showInfoMessage(String message) {
        JOptionPane.showMessageDialog(null, message,
                "Info", JOptionPane.INFORMATION_MESSAGE);
    }
}
