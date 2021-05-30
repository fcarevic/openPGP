package etf.openpgp.cf170065dsd1700145d.keyGeneration;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;

public class PGPKeyImporter {

    public static PGPPublicKeyRing importPUKeyRIng(String path) throws IOException {
        try (InputStream inputStream = new FileInputStream(path);
                InputStream decoderStream = PGPUtil.getDecoderStream(inputStream)) {
            return new PGPPublicKeyRing(decoderStream, new JcaKeyFingerprintCalculator());
        }
    }

    public static PGPSecretKeyRing importSCKeyRing(String path) throws IOException, PGPException {
        try (InputStream inputStream = new FileInputStream(path);
                InputStream decoderStream = PGPUtil.getDecoderStream(inputStream)) {
            return new PGPSecretKeyRing(decoderStream, new JcaKeyFingerprintCalculator());
        }
    }

    public static PGPSecretKeyRingCollection importSCKeyRingCollection(String path) {
        try (InputStream inputStream = new FileInputStream(path);
                InputStream decoderStream = PGPUtil.getDecoderStream(inputStream)) {
            return new PGPSecretKeyRingCollection(decoderStream, new JcaKeyFingerprintCalculator());
        } catch (IOException | PGPException ex) {
            return null;
        }
    }

    public static PGPPublicKeyRingCollection importPUKeyRingCollection(String path) {
        try (InputStream inputStream = new FileInputStream(path);
                InputStream decoderStream = PGPUtil.getDecoderStream(inputStream)) {
            return new PGPPublicKeyRingCollection(decoderStream, new JcaKeyFingerprintCalculator());
        } catch (IOException | PGPException ex) {
            return null;
        }
    }

}
