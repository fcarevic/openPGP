package etf.openpgp.cf170065dsd170145d.keyGeneration;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 *
 * @author Dušan Stijović
 */
public class PGPKeyImporter {

    /**
     *
     * @param path absolute path of file that contains public key ring
     * @return imported public key ring
     * @throws IOException
     */
    public static PGPPublicKeyRing importPUKeyRIng(String path) throws IOException {
        try (InputStream inputStream = new FileInputStream(path);
                InputStream decoderStream = PGPUtil.getDecoderStream(inputStream)) {
            return new PGPPublicKeyRing(decoderStream, new JcaKeyFingerprintCalculator());
        }
    }

    /**
     *
     * @param path absolute path of file that contains secret key ring
     * @return imported secret key ring
     * @throws IOException
     * @throws PGPException
     */
    public static PGPSecretKeyRing importSCKeyRing(String path) throws IOException, PGPException {
        try (InputStream inputStream = new FileInputStream(path);
                InputStream decoderStream = PGPUtil.getDecoderStream(inputStream)) {
            return new PGPSecretKeyRing(decoderStream, new JcaKeyFingerprintCalculator());
        }
    }

    /**
     *
     * @param path absolute path of file that contains secret key ring
     * collection
     * @return imported secret key ring collection
     */
    public static PGPSecretKeyRingCollection importSCKeyRingCollection(String path) {
        try (InputStream inputStream = new FileInputStream(path);
                InputStream decoderStream = PGPUtil.getDecoderStream(inputStream)) {
            return new PGPSecretKeyRingCollection(decoderStream, new JcaKeyFingerprintCalculator());
        } catch (IOException | PGPException ex) {
            return null;
        }
    }

    /**
     *
     * @param path absolute path of file that contains public key ring
     * collection
     * @return imported public key ring collection
     */
    public static PGPPublicKeyRingCollection importPUKeyRingCollection(String path) {
        try (InputStream inputStream = new FileInputStream(path);
                InputStream decoderStream = PGPUtil.getDecoderStream(inputStream)) {
            return new PGPPublicKeyRingCollection(decoderStream, new JcaKeyFingerprintCalculator());
        } catch (IOException | PGPException ex) {
            return null;
        }
    }

}
