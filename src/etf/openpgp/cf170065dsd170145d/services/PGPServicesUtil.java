package etf.openpgp.cf170065dsd170145d.services;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

/**
 * Utility class. Contains implementations of PGP services: encryption, digital
 * signature, compression and radix64 conversion
 *
 * @author Filip Carevic
 *
 */
public class PGPServicesUtil {

    /**
     * Procedure for radix64 data encoding
     *
     *
     * @param data
     * @return encoded data
     * @throws IOException
     *
     */
    public static byte[] encodeRadix64(byte[] data) throws IOException {
        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        org.bouncycastle.bcpg.ArmoredOutputStream armoredOutputStream = new org.bouncycastle.bcpg.ArmoredOutputStream(byteOutputStream);
        armoredOutputStream.write(data);
        armoredOutputStream.close();
        byte[] encodedData = byteOutputStream.toByteArray();
        byteOutputStream.close();
        return encodedData;

    }

    /**
     *
     * Decodes radix64 encoded data
     *
     * @param data
     * @return decoded data
     * @throws IOException
     */
    public static byte[] decodeRadix64(byte[] data) throws IOException {
        return PGPUtil.getDecoderStream(new ByteArrayInputStream(data)).readAllBytes();

    }

    /**
     * Compresses data using specified algorithm
     *
     * @param data -data to be compressed
     * @param algorithm - Compression algorithm
     * @return compressed data
     * @throws IOException
     */
    public static byte[] compress(byte[] data, int algorithm) throws IOException {
        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        PGPCompressedDataGenerator compressionGenerator = new PGPCompressedDataGenerator(algorithm);
        OutputStream compressedStream = compressionGenerator.open(byteOutputStream); // open it with the final destination
        compressedStream.write(data);
        compressedStream.close();
        byte[] compressedData = byteOutputStream.toByteArray();
        byteOutputStream.close();
        return compressedData;
    }

    /**
     * Decompresses data. Compression algorithm is deduced from metadata.
     *
     * @param data -compressed data
     * @return decompressed data
     * @throws Exception
     */
    public static byte[] decompress(byte[] data) throws Exception {

        JcaPGPObjectFactory pgpFactory = new JcaPGPObjectFactory(data);
        Object object = pgpFactory.nextObject();
        if (!(object instanceof PGPCompressedData)) {
            throw new ExtendedInfoPGPException("Unable to decompress message");
        }
        return ((PGPCompressedData) object).getDataStream().readAllBytes();
    }

    /**
     * Encrypt data using symmetric encription algorithm. Session key is
     * randomly generated. Session key is encripred independently using
     * assymetric public keys provided as parameter.
     *
     *
     * @param data - data to be encrypted
     * @param keys - public keys of all recepients
     * @param algorithm - Symmetric algorithm used for encryption
     * @return encrypted data
     * @throws IOException
     * @throws PGPException
     */
    public static byte[] encrypt(byte[] data, List<PGPPublicKey> keys, int algorithm) throws IOException, PGPException {

        OutputStream outputStream = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator encryptionGenerator = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(algorithm).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));
        for (PGPPublicKey key : keys) {
            encryptionGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(key).setProvider("BC"));
        }
        // STA RADI OVO
        OutputStream encryptedOutputStream = encryptionGenerator.open(outputStream, data.length);

        encryptedOutputStream.write(data);
        encryptedOutputStream.close();

        return ((ByteArrayOutputStream) outputStream).toByteArray();
    }

    /**
     * Decrypts byte of data. Session key, Private key, assymetric and symmetric
     * decryption algorithms are deduced from metadata of data
     *
     * @param data - data to be decrypted
     * @param password - passphrase to extract private key
     * @return decrypted data
     * @throws PGPException
     * @throws IOException
     * @throws ExtendedPGPException
     * @throws ExtendedInfoPGPException
     */
    public static byte[] decrypt(byte[] data, char[] password) throws PGPException, IOException, ExtendedPGPException, ExtendedInfoPGPException {

        JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(data);
        Object object = objectFactory.nextObject();
        if (object instanceof PGPMarker) {
            object = objectFactory.nextObject();
        }

        if (object instanceof PGPEncryptedDataList) {
            PGPEncryptedDataList enc = (PGPEncryptedDataList) object;
            java.util.Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();
                PGPSecretKeyRing privateKeyRing = getPrivateKeyRing(pbe.getKeyID());
                //TODO DOHVATANJE RINGA KLJUCEVA

                if (privateKeyRing != null) {
                    java.util.Iterator<PGPSecretKey> iterPriv = privateKeyRing.getSecretKeys();
                    PGPSecretKey masterKey = iterPriv.next();
                    PGPSecretKey secretKey = iterPriv.next();

                    PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                            .setProvider("BC").build(password));
                    System.out.println("Decrypt Private extracted wanted id:\t" + privateKey.getKeyID());
                    System.out.println("Decrypt Private Secret NONEXTRACTED wanted id:\t" + secretKey.getKeyID());

                    PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey);
                    InputStream decryptedStream = pbe.getDataStream(dataDecryptorFactory);
                    return decryptedStream.readAllBytes();
                } else {
                    throw new ExtendedPGPException("Decryption private key  not found");
                }
            }
        } else {
            throw new ExtendedInfoPGPException("Decryption phase error");
        }
        return null;

    }

    /**
     * Extracts signers info from signed data.
     *
     * @param data -signed data
     * @return signer info
     * @throws IOException
     */
    public static String extractMessageAuthor(byte[] data) throws IOException {
        JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(data);
        Object object = objectFactory.nextObject();

        if (object instanceof PGPOnePassSignatureList) {
            PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) object;
            PGPOnePassSignature onePassSignature = onePassSignatureList.get(0);

            long keyId = onePassSignature.getKeyID();
            PGPPublicKey publicKey = getMasterPublicKeyByID(keyId);
            return publicKey.getUserIDs().next();
        }
        return null;
    }

    /**
     * Verifies signature of signed message.
     *
     * @param data - signed data to verify
     * @return indicator if signature is verified
     * @throws Exception - ExtendedPGPException if tampering with message was
     * detected
     */
    public static boolean verifySignature(byte[] data) throws Exception {
        JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(data);
        Object object = objectFactory.nextObject();

        if (object instanceof PGPOnePassSignatureList) {
            PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) object;
            PGPOnePassSignature onePassSignature = onePassSignatureList.get(0);

            long keyId = onePassSignature.getKeyID();

            PGPPublicKey publicKey = getPublicKeyByID(keyId);
            if (publicKey == null) {
                throw new ExtendedPGPException("Key for signature verification not found");
            }

            onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);

            InputStream toVerify = ((PGPLiteralData) objectFactory.nextObject()).getInputStream();

            onePassSignature.update(toVerify.readAllBytes());

            PGPSignatureList signatureList = (PGPSignatureList) objectFactory.nextObject();
            PGPSignature signature = signatureList.get(0);

            if (onePassSignature.verify(signature)) {
                System.out.println("Received message from: " + getMasterPublicKeyByID(keyId).getUserIDs().next());

                return true;
            } else {
                throw new ExtendedPGPException("Verification failed, signature integrity corrupted");

            }
        }
        throw new ExtendedInfoPGPException("Verification error");
    }

    /**
     *
     * Signs message with private key
     *
     *
     * @param data -data to be signed
     * @param privateKey -signing key
     * @param algorithm - Signning algorithm
     * @param filename - file to read data from
     * @return signed data
     * @throws PGPException
     * @throws IOException
     */
    public static byte[] sign(byte[] data, PGPPrivateKey privateKey, int algorithm, String filename) throws PGPException, IOException {

        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(algorithm, PGPUtil.SHA256).setProvider("BC"));

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        BCPGOutputStream helperStream = new BCPGOutputStream(byteStream);

        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        signatureGenerator.generateOnePassVersion(false).encode(helperStream);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream os = lGen.open(helperStream, PGPLiteralData.BINARY, filename, data.length, new Date());
        InputStream is = new ByteArrayInputStream(data);

        int ch;

        while ((ch = is.read()) >= 0) {
            signatureGenerator.update((byte) ch);
            os.write(ch);
        }

        lGen.close();

        signatureGenerator.generate().encode(helperStream);

        byte[] signed = byteStream.toByteArray();

        byteStream.close();
        helperStream.close();
        return signed;

    }

    /**
     * Generated literal Data envelope from data.
     *
     * @param data
     * @param filename - input filename
     * @return
     * @throws IOException
     */
    public static byte[] generateLiteralData(byte[] data, String filename) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        BCPGOutputStream helperStream = new BCPGOutputStream(byteStream);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream os = lGen.open(helperStream, PGPLiteralData.BINARY, filename, data.length, new Date());
        InputStream is = new ByteArrayInputStream(data);

        int ch;

        while ((ch = is.read()) >= 0) {
            os.write((byte) ch);
        }

        lGen.close();

        byte[] literalData = byteStream.toByteArray();

        byteStream.close();
        helperStream.close();
        return literalData;

    }

    /**
     * Extracts data from LiteralData envelopes
     *
     * @param data
     * @return plain data
     * @throws IOException
     */
    public static byte[] parseLiteralData(byte[] data) throws IOException {
        JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(data);
        Object object = objectFactory.nextObject();
        while (object != null) {
            if (object instanceof PGPLiteralData) {

                PGPLiteralData literalData = (PGPLiteralData) object;
                InputStream inputStream = literalData.getInputStream();
                return inputStream.readAllBytes();

            }
            object = objectFactory.nextObject();
        }

        return data;

    }

    /**
     *
     * @param message
     */
    public static void reportError(String message) {
        System.err.println(message);
    }

    /**
     * Gets public key from public key ring collection
     *
     * @param id
     * @return
     */
    private static PGPPublicKey getPublicKeyByID(long id) {
        System.out.println("Public wanted id(verify signing):\t" + id);

//        return PGPAsymmetricKeyUtil.getPUKeyFromPURing(PGPMessageSenderDriver.util.getPUKeyRingFromPUKeyRingCollection(id));
        return getMasterPublicKeyByID(id);
    }

    /**
     * Gets master key from public key ring collection
     *
     * @param id
     * @return
     */
    private static PGPPublicKey getMasterPublicKeyByID(long id) {
        PGPPublicKeyRing puKeyRingFromPUKeyRingCollection = PGPMessageSenderDriver.util.getPUKeyRingFromPUKeyRingCollection(id);
        if (puKeyRingFromPUKeyRingCollection == null) {
            return null;
        }
        return puKeyRingFromPUKeyRingCollection.getPublicKeys().next();
    }

    /**
     *
     * Gets ptivate key from secret key ring collection
     *
     * @param id
     * @return
     */
    private static PGPSecretKeyRing getPrivateKeyRing(long id) {
        System.out.println("PRIVATE WANTED (decrypt): \t" + id);
        return PGPMessageSenderDriver.util.getSCKeyRingFromSCKeyRingCollection(id);

    }

    /**
     * Not to be used Testing purposes only
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            byte[] data = IOUtil.readFromFile("srpski.txt");
            data = compress(data, CompressionAlgorithmTags.ZIP);
            data = encodeRadix64(data);
            IOUtil.writeToFile("srpski-compressed.txt", data);

            data = IOUtil.readFromFile("srpski-compressed.txt");
            data = decodeRadix64(data);
            data = decompress((data));
            IOUtil.writeToFile("srpski-decompressed.txt", data);

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            ErrorReportUtil.reportError(e);
        }

    }
}
