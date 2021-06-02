package rs.ac.bg.etf.zp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.Iterator;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import etf.openpgp.cf170065dsd1700145d.keyGeneration.PGPAsymmetricKeyUtil;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PGPMessageSenderDriver {

    public static PGPAsymmetricKeyUtil util;

    private boolean requiresSignature;
    private boolean requiresCompression;
    private boolean requiresEncryption;
    private boolean requiresRadix64;
    private byte[] data;
    private String messageAuthor=null;
    private PGPPrivateKey signingKey;
    private int signingAlgorithm;
    private List<PGPPublicKey> encryptionKey;
    private int encryptionAlgorithm;
    private int compressionAlgorithm = CompressionAlgorithmTags.ZIP;

    private String password;
    private String inputFile;
    private String outputFile;

    public void setPassword(String password) {
        this.password = password;
    }
    public String getMessageAuthor(){
        return messageAuthor;
    }
    public boolean isRequiresSignature() {
        return requiresSignature;
    }

    public void setInputFile(String inputFile) {
        this.inputFile = inputFile;
    }

    public void setOutputFile(String outputFile) {
        this.outputFile = outputFile;
    }
    

    public void setRequiresSignature(boolean requiresSignature) {
        this.requiresSignature = requiresSignature;
    }

    public boolean isRequiresCompression() {
        return requiresCompression;
    }

    public void setRequiresCompression(boolean requiresCompression) {
        this.requiresCompression = requiresCompression;
    }

    public boolean isRequiresEncryption() {
        return requiresEncryption;
    }

    public void setRequiresEncryption(boolean requiresEncryption) {
        this.requiresEncryption = requiresEncryption;
    }

    public boolean isRequiresRadix64() {
        return requiresRadix64;
    }

    public void setRequiresRadix64(boolean requiresRadix64) {
        this.requiresRadix64 = requiresRadix64;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

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

    public void configSignature(boolean isRequired, int algorithm, PGPPrivateKey signingKey) {
        this.requiresSignature = isRequired;
        this.signingKey = signingKey;
        this.signingAlgorithm = algorithm;
    }

    public void configEncryption(boolean isRequired, List<Long> publicKeyIDs, int algorithm) {
        List<PGPPublicKey> publicKeysList = new LinkedList<>();
        for (long keyId : publicKeyIDs) {
            publicKeysList.add(PGPAsymmetricKeyUtil.getPUKeyFromPURing(util.getPUKeyRingFromPUKeyRingCollection(keyId)));
        }

        this.configEncryption(isRequired, algorithm, publicKeysList);

    }

    public void configEncryption(boolean isRequired, int algorithm, List<PGPPublicKey> encryptionKey) {

        this.requiresEncryption = isRequired;
        this.encryptionKey = encryptionKey;
        this.encryptionAlgorithm = algorithm;
    }

    public void configCompression(boolean isRequired, int algorithm) {
        this.requiresCompression = isRequired;
        this.compressionAlgorithm = algorithm;
    }

    public byte[] encrypt() throws PGPException, IOException {
        if (requiresSignature) {
            this.data = PGPServicesUtil.sign(this.data, signingKey, signingAlgorithm, outputFile);
        } else 
            this.data=PGPServicesUtil.generateLiteralData(data, outputFile);
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

    
    
    public void decodeDecryptoinPhase(){
        try {

            data = PGPServicesUtil.decodeRadix64(data);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            ErrorReportUtil.reportAndWriteToFile(e, outputFile, data);
        }
    
    }
    
    public void decryptDecryptionPhase() throws PGPException, ExtendedPGPException{
        try {
            data = PGPServicesUtil.decrypt(data, password.toCharArray());
        } catch (IOException|ExtendedInfoPGPException e) {
            // TODO Auto-generated catch block
            ErrorReportUtil.reportAndWriteToFile(e, outputFile, data);
        }
    
    }
    
    public void decompressDecryptionPhase() throws Exception{
            try {
            data = PGPServicesUtil.decompress(data);
        } catch (ExtendedInfoPGPException e) {
            ErrorReportUtil.reportAndWriteToFile(e, outputFile, data);
        }

    }
    
    public void literalDataDecryptionPhase(){
            try {
            data = PGPServicesUtil.parseLiteralData(data);
        } catch (IOException e) {
            ErrorReportUtil.reportAndWriteToFile(e, outputFile, data);
        }

    }
    public void verifySignatureDecriptionPhase() throws Exception{
    try {
            PGPServicesUtil.verifySignature(data);
            this.messageAuthor=PGPServicesUtil.extractMessageAuthor(data);
        } catch ( IOException| ExtendedInfoPGPException e) {
            // TODO Auto-generated catch block
            ErrorReportUtil.reportError(e);
         
        }
    }

    public void readFileToDecrypt(String inputFile){
        try {
            this.data = IOUtil.readFromFile(inputFile);
        } catch (IOException ex) {
            Logger.getLogger(PGPMessageSenderDriver.class.getName()).log(Level.SEVERE, null, ex);
        }
          
    }
    
    public void writeToFileDecrypted(String outputFile){
        try {
            IOUtil.writeToFile(outputFile, data);
        } catch (IOException ex) {
            Logger.getLogger(PGPMessageSenderDriver.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
   

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
