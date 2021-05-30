/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.cf170065dsd1700145d.GUI;

import javax.swing.JFrame;
import javax.swing.JOptionPane;

/**
 *
 * @author Dušan
 */
public class GUIUtil {

    public static boolean checkEmail(String email) {
        return true;
    }

    public static void showErrorMessage(String message) {
        JOptionPane.showMessageDialog(null, message,
                "Error", JOptionPane.ERROR_MESSAGE);
    }

    public static void showInfoMessage(String message) {
        JOptionPane.showMessageDialog(null, message,
                "Info", JOptionPane.INFORMATION_MESSAGE);
    }
}
