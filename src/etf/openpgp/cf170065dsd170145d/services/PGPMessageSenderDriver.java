package etf.openpgp.cf170065dsd170145d.services;

import java.io.IOException;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import etf.openpgp.cf170065dsd170145d.keyGeneration.PGPAsymmetricKeyUtil;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Driver class for PGP services
 *
 * @author Filip Carevic
 *
 */
public class PGPMessageSenderDriver {

    /**
     *
     */
    public static PGPAsymmetricKeyUtil util;

    private boolean requiresSignature;
    private boolean requiresCompression;
    private boolean requiresEncryption;
    private boolean requiresRadix64;
    private byte[] data;
    private String messageAuthor = null;
    private PGPPrivateKey signingKey;
    private int signingAlgorithm;
    private List<PGPPublicKey> encryptionKey;
    private int encryptionAlgorithm;
    private int compressionAlgorithm = CompressionAlgorithmTags.ZIP;

    private String password;
    private String inputFile;
    private String outputFile;

    /**
     *
     * @param password
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     *
     * @return
     */
    public String getMessageAuthor() {
        return messageAuthor;
    }

    /**
     *
     * @return
     */
    public boolean isRequiresSignature() {
        return requiresSignature;
    }

    /**
     *
     * @param inputFile
     */
    public void setInputFile(String inputFile) {
        this.inputFile = inputFile;
    }

    /**
     *
     * @param outputFile
     */
    public void setOutputFile(String outputFile) {
        this.outputFile = outputFile;
    }

    /**
     *
     * @param requiresSignature
     */
    public void setRequiresSignature(boolean requiresSignature) {
        this.requiresSignature = requiresSignature;
    }

    /**
     *
     * @return
     */
    public boolean isRequiresCompression() {
        return requiresCompression;
    }

    /**
     *
     * @param requiresCompression
     */
    public void setRequiresCompression(boolean requiresCompression) {
        this.requiresCompression = requiresCompression;
    }

    /**
     *
     * @return
     */
    public boolean isRequiresEncryption() {
        return requiresEncryption;
    }

    /**
     *
     * @param requiresEncryption
     */
    public void setRequiresEncryption(boolean requiresEncryption) {
        this.requiresEncryption = requiresEncryption;
    }

    /**
     *
     * @return
     */
    public boolean isRequiresRadix64() {
        return requiresRadix64;
    }

    /**
     *
     * @param requiresRadix64
     */
    public void setRequiresRadix64(boolean requiresRadix64) {
        this.requiresRadix64 = requiresRadix64;
    }

    /**
     *
     * @return
     */
    public byte[] getData() {
        return data;
    }

    /**
     *
     * @param data
     */
    public void setData(byte[] data) {
        this.data = data;
    }

    /**
     * configures whether signature in sending message is required
     *
     * @param isRequired
     * @param privateKeyID - signign key id
     * @throws PGPException
     */
    public void configSignature(boolean isRequired, long privateKeyID) throws PGPException {
        if (isRequired) {
//            PGPSecretKey secretKey = PGPAsymmetricKeyUtil.getSCKeyFromSCRing(util.getSCKeyRingFromSCKeyRingCollection(privateKeyID));
            PGPSecretKeyRing scKeyRingFromSCKeyRingCollection = util.getSCKeyRingFromSCKeyRingCollection(privateKeyID);
            PGPSecretKey secretKey = scKeyRingFromSCKeyRingCollection.getSecretKeys().next();
            PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                    .setProvider("BC").build(password.toCharArray()));
            System.out.println("rs.ac.bg.etf.zp.PGPMessageSenderDriver.configSignature() DSA ID: " + privateKey.getKeyID());
            this.configSignature(isRequired, privateKey.getPublicKeyPacket().getAlgorithm(), privateKey);

        } else {
            this.requiresSignature = false;
        }
    }

    /**
     * configures whether signature in sending message is required
     *
     * @param isRequired
     * @param algorithm -signing algorithm
     * @param signingKey
     */
    public void configSignature(boolean isRequired, int algorithm, PGPPrivateKey signingKey) {
        this.requiresSignature = isRequired;
        this.signingKey = signingKey;
        this.signingAlgorithm = algorithm;
    }

    /**
     * configures whether encryption in sending message is required
     *
     * @param isRequired
     * @param publicKeyIDs - public keys used for encryption of session key
     * @param algorithm - symmetric algorithm used in message encryption
     */
    public void configEncryption(boolean isRequired, List<Long> publicKeyIDs, int algorithm) {
        List<PGPPublicKey> publicKeysList = new LinkedList<>();
        for (long keyId : publicKeyIDs) {
            publicKeysList.add(PGPAsymmetricKeyUtil.getPUKeyFromPURing(util.getPUKeyRingFromPUKeyRingCollection(keyId)));
        }

        this.configEncryption(isRequired, algorithm, publicKeysList);

    }

    /**
     * configures whether encryption in sending message is required
     *
     * @param isRequired
     * @param algorithm -symmetric algorithm used for message encryption
     * @param encryptionKey - public keys used for encryption of session key
     */
    public void configEncryption(boolean isRequired, int algorithm, List<PGPPublicKey> encryptionKey) {

        this.requiresEncryption = isRequired;
        this.encryptionKey = encryptionKey;
        this.encryptionAlgorithm = algorithm;
    }

    /**
     * configures whether compression is required in message sending
     *
     * @param isRequired
     * @param algorithm - compression algorithm to be used
     */
    public void configCompression(boolean isRequired, int algorithm) {
        this.requiresCompression = isRequired;
        this.compressionAlgorithm = algorithm;
    }

    /**
     * Sending phase. Requires all PGP services to be configured before use
     *
     * @return processed data
     * @throws PGPException
     * @throws IOException
     */
    public byte[] encrypt() throws PGPException, IOException {
        if (requiresSignature) {
            this.data = PGPServicesUtil.sign(this.data, signingKey, signingAlgorithm, outputFile);
        } else {
            this.data = PGPServicesUtil.generateLiteralData(data, outputFile);
        }
        if (requiresCompression) {
            this.data = PGPServicesUtil.compress(this.data, compressionAlgorithm);
        }
        if (requiresEncryption) {
            this.data = PGPServicesUtil.encrypt(this.data, encryptionKey, encryptionAlgorithm);
        }
        if (requiresRadix64) {
            this.data = PGPServicesUtil.encodeRadix64(this.data);
        }
        return this.data;
    }

    /**
     * Decoding phase of receiving message Decoded data is stored in attribute -
     * data
     */
    public void decodeDecryptoinPhase() {
        try {

            data = PGPServicesUtil.decodeRadix64(data);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            ErrorReportUtil.reportAndWriteToFile(e, outputFile, data);
        }

    }

    /**
     * Decryption phase of receiving message Decrypted data is stored in
     * attribute - data
     *
     * @throws PGPException
     * @throws ExtendedPGPException
     */
    public void decryptDecryptionPhase() throws PGPException, ExtendedPGPException {
        try {
            data = PGPServicesUtil.decrypt(data, password.toCharArray());
        } catch (IOException | ExtendedInfoPGPException e) {
            // TODO Auto-generated catch block
            ErrorReportUtil.reportAndWriteToFile(e, outputFile, data);
        }

    }

    /**
     * Decompression phase of receiving message Decompressed data is stored in
     * attribute - data
     *
     * @throws Exception
     */
    public void decompressDecryptionPhase() throws Exception {
        try {
            data = PGPServicesUtil.decompress(data);
        } catch (ExtendedInfoPGPException e) {
            ErrorReportUtil.reportAndWriteToFile(e, outputFile, data);
        }

    }

    /**
     *
     */
    public void literalDataDecryptionPhase() {
        try {
            data = PGPServicesUtil.parseLiteralData(data);
        } catch (IOException e) {
            ErrorReportUtil.reportAndWriteToFile(e, outputFile, data);
        }

    }

    /**
     *
     * @throws Exception -if signature not present, or similar error
     */
    public void verifySignatureDecriptionPhase() throws Exception {
        try {
            PGPServicesUtil.verifySignature(data);
            this.messageAuthor = PGPServicesUtil.extractMessageAuthor(data);
        } catch (IOException | ExtendedInfoPGPException e) {
            // TODO Auto-generated catch block
            ErrorReportUtil.reportError(e);

        }
    }

    /**
     *
     * @param inputFile
     */
    public void readFileToDecrypt(String inputFile) {
        try {
            this.data = IOUtil.readFromFile(inputFile);
        } catch (IOException ex) {
            Logger.getLogger(PGPMessageSenderDriver.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    /**
     *
     * @param outputFile
     */
    public void writeToFileDecrypted(String outputFile) {
        try {
            IOUtil.writeToFile(outputFile, data);
        } catch (IOException ex) {
            Logger.getLogger(PGPMessageSenderDriver.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Crafts PGP message from input file
     *
     * @param inputFile - messate to be proccesed
     * @param outputFile -where crafted message is stored
     */
    public void encryptMessage(String inputFile, String outputFile) {
        try {
            this.inputFile = inputFile;
            this.outputFile = outputFile;
            this.data = IOUtil.readFromFile(inputFile);
            byte[] processedData = encrypt();
            IOUtil.writeToFile(outputFile, processedData);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            ErrorReportUtil.reportAndWriteToFile(e, outputFile, data);

        }

    }

    /**
     *
     * @param args
     */
    public static void main(String[] args) {

        String name1 = "Nikola Vucenovic";
        String mail1 = " <nikolavucenovic97@gmail.com>";
        String password1 = "Sifra123";
        String name2 = "Milo Tomasevic";
        String mail2 = "<milo@gmail.com>";
        String password2 = "Sifra123";

        try {
            Security.addProvider(new BouncyCastleProvider());
            util = new PGPAsymmetricKeyUtil();;
            util.generateNewKeyRing(name1, mail1, password1, "DSA", 1024);
            util.generateNewKeyRing(name2, mail2, password2, "ELGAMAL", 1024);

            PGPSecretKeyRing singatureRing = util.getSecretKeyRings().get(0);
            PGPSecretKeyRing encRing = util.getSecretKeyRings().get(1);

            Iterator<PGPPublicKey> iterPublic = encRing.getPublicKeys();
            iterPublic.next();

            PGPPublicKey publicKey = iterPublic.next();

            int alg = PGPEncryptedData.TRIPLE_DES;

            PGPMessageSenderDriver ms = new PGPMessageSenderDriver();

            ms.setRequiresCompression(true);
            ms.setRequiresRadix64(true);
//			ms.configEncryption(true,  alg, publicKey);
            System.out.println("Public encrypt id:\t" + publicKey.getKeyID());

            PGPSecretKeyRing privateKeyRing = singatureRing;
            //TODO DOHVATANJE RINGA KLJUCEVA
            PGPPrivateKey privateKey = null;
            int signAlg = 1;
            if (privateKeyRing != null) {
                java.util.Iterator<PGPSecretKey> iterPriv = privateKeyRing.getSecretKeys();
                PGPSecretKey masterKey = iterPriv.next();
                PGPSecretKey secretKey = iterPriv.next();
                System.out.println("Secret sign id:\t" + secretKey.getKeyID());
                System.out.println(masterKey.isSigningKey());
                signAlg = secretKey.getPublicKey().getAlgorithm();

                privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                        .setProvider("BC").build(password1.toCharArray()));
                System.out.println("Private sign id:\t" + privateKey.getKeyID());
            }

            ms.configSignature(false, signAlg, privateKey);

            String name = "srpski";
//            ms.processMessage(name + ".txt", name + "-encrypted.txt", true);

            ms.setPassword("Sifra123");
//            ms.processMessage(name + "-encrypted.txt", name + "-decrypted.txt", false);
            System.out.println("Finished sending");

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

}
