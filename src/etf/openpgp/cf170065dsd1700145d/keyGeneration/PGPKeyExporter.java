package etf.openpgp.cf170065dsd1700145d.keyGeneration;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;

import java.io.FileOutputStream;
import java.io.IOException;

public class PGPKeyExporter {

    public static void exportPUKey(PGPPublicKeyRing pgpPUKeyRing, String path) throws IOException {
        writeToFile(pgpPUKeyRing, path);
    }

    public static void exportSCKey(PGPSecretKeyRing pgpSecretKeyRing, String path) throws IOException {
        writeToFile(pgpSecretKeyRing, path);
    }

    private static void writeToFile(PGPKeyRing pgpKeyRing, String path) throws IOException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(path);
             ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(fileOutputStream)
        ) {
            pgpKeyRing.encode(armoredOutputStream);
        }
    }

    public static void exportKeySCRingCollection(PGPSecretKeyRingCollection pgpSCKeyRingCollection, String path) throws IOException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(path);
             ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(fileOutputStream)
        ) {
            pgpSCKeyRingCollection.encode(armoredOutputStream);
        }
    }

    public static void exportKeyPURingCollection(PGPPublicKeyRingCollection pgpPUKeyRingCollection, String path) throws IOException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(path);
             ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(fileOutputStream)
        ) {
            pgpPUKeyRingCollection.encode(armoredOutputStream);
        }
    }


}
