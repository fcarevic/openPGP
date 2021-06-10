package etf.openpgp.cf170065dsd170145d.keyGeneration;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;

import java.io.FileOutputStream;
import java.io.IOException;

/**
 *
 * @author Dušan Stijović
 */
public class PGPKeyExporter {

    /**
     *
     * @param pgpPUKeyRing public key ring to be exported
     * @param path absolute path of file in which public key ring will be
     * exported
     * @throws IOException
     */
    public static void exportPUKey(PGPPublicKeyRing pgpPUKeyRing, String path) throws IOException {
        writeToFile(pgpPUKeyRing, path);
    }

    /**
     *
     * @param pgpSecretKeyRing secret key ring to be exported
     * @param path absolute path of file in which secret key ring will be
     * exported
     * @throws IOException
     */
    public static void exportSCKey(PGPSecretKeyRing pgpSecretKeyRing, String path) throws IOException {
        writeToFile(pgpSecretKeyRing, path);
    }

    /**
     *
     * @param pgpKeyRing key ring to br exported
     * @param path absolute path of file in which key ring will be
     * @throws IOException
     */
    private static void writeToFile(PGPKeyRing pgpKeyRing, String path) throws IOException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(path);
                ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(fileOutputStream)) {
            pgpKeyRing.encode(armoredOutputStream);
        }
    }

    /**
     *
     * @param pgpSCKeyRingCollection
     * @param path absolute path of file in which secret key ring collection
     * will be exported
     * @throws IOException
     */
    public static void exportKeySCRingCollection(PGPSecretKeyRingCollection pgpSCKeyRingCollection, String path) throws IOException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(path);
                ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(fileOutputStream)) {
            pgpSCKeyRingCollection.encode(armoredOutputStream);
        }
    }

    /**
     *
     * @param pgpPUKeyRingCollection
     * @param path absolute path of file in which public key ring collection
     * will be exported
     * @throws IOException
     */
    public static void exportKeyPURingCollection(PGPPublicKeyRingCollection pgpPUKeyRingCollection, String path) throws IOException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(path);
                ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(fileOutputStream)) {
            pgpPUKeyRingCollection.encode(armoredOutputStream);
        }
    }

}
