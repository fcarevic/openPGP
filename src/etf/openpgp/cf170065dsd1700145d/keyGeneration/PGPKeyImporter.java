package etf.openpgp.cf170065dsd1700145d.keyGeneration;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

public class PGPKeyImporter {

    public static PGPPublicKeyRing importPUKeyRIng(String path) throws IOException {
        try (InputStream inputStream = new FileInputStream(path);
             InputStream decoderStream = PGPUtil.getDecoderStream(inputStream)
        ) {
            return new PGPPublicKeyRing(decoderStream, new JcaKeyFingerprintCalculator());
        }
    }

    public static PGPSecretKeyRing importSCKeyRing(String path) throws IOException, PGPException {
        try (InputStream inputStream = new FileInputStream(path);
             InputStream decoderStream = PGPUtil.getDecoderStream(inputStream)
        ) {
            return new PGPSecretKeyRing(decoderStream, new JcaKeyFingerprintCalculator());
        }
    }

    public static PGPSecretKeyRingCollection importSCKeyRingCollection(String path) throws IOException, PGPException {
        try (InputStream inputStream = new FileInputStream(path);
             InputStream decoderStream = PGPUtil.getDecoderStream(inputStream)
        ) {
            return new PGPSecretKeyRingCollection(decoderStream, new JcaKeyFingerprintCalculator());
        }
    }


    public static PGPPublicKeyRingCollection importPUKeyRingCollection(PGPPublicKeyRingCollection pgpPUKeyRingCollection, String path) throws IOException, PGPException {
        try (InputStream inputStream = new FileInputStream(path);
             InputStream decoderStream = PGPUtil.getDecoderStream(inputStream)
        ) {
            return new PGPPublicKeyRingCollection(decoderStream, new JcaKeyFingerprintCalculator());
        }
    }

}
