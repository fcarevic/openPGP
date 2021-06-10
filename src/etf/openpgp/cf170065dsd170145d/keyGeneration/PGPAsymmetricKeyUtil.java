package etf.openpgp.cf170065dsd170145d.keyGeneration;

import java.io.IOException;
import java.security.InvalidKeyException;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class PGPAsymmetricKeyUtil {

    private PGPSecretKeyRingCollection pgpSecretKeyRingCollection;
//My public-private keys collections
    //Receivers public keys collections
    private PGPPublicKeyRingCollection pgpPublicKeyRingCollection;

    private static final Map<String, Integer> algorithms = Map.of(
            "DSA", PGPPublicKey.DSA,
            "ELGAMAL", PGPPublicKey.ELGAMAL_ENCRYPT
    );

    public static Map<String, Integer> getAlgorithms() {
        return algorithms;
    }

    public static String getAlgorithmByID(int algorithmid) {

        for (Map.Entry<String, Integer> entry : algorithms.entrySet()) {
            if (entry.getValue() == algorithmid) {
                return entry.getKey();
            }
        }
        return "not found";
    }

    private final static String SECURITY_PROVIDER = "BC";
    private final static String MASTER_KEY_ALGORITHM = "DSA";
    private final static int MASTER_KEY_SIZE = 1024;

    private final static String PU_KEY_RING_COLLECTION = "public.ring";
    private final static String SC_KEY_RING_COLLECTION = "secret.ring";

    public PGPAsymmetricKeyUtil() {
        try {

            this.pgpPublicKeyRingCollection = PGPKeyImporter.importPUKeyRingCollection(PU_KEY_RING_COLLECTION);
            this.pgpSecretKeyRingCollection = PGPKeyImporter.importSCKeyRingCollection(SC_KEY_RING_COLLECTION);

            if (this.pgpPublicKeyRingCollection == null) {
                this.pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(new ArrayList<>());
            }

            if (this.pgpSecretKeyRingCollection == null) {
                this.pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(new ArrayList<>());
            }
        } catch (IOException | PGPException ex) {

        }
    }

    private KeyPair generateNewKeyPair(String algorithm, int keySize, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    private void addSCKeyRingToSCRingCollection(PGPSecretKeyRing pgpSecretKeyRing) {
        pgpSecretKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(pgpSecretKeyRingCollection, pgpSecretKeyRing);
    }

    private void addPUKeyRingToPURingCollection(PGPPublicKeyRing pgpPublicKeyRing) {
        pgpPublicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(pgpPublicKeyRingCollection, pgpPublicKeyRing);
    }

    public boolean generateNewKeyRing(String userName, String userMail, String userPassword, String algorithm, int keySize) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        GenerateKeyRingTask generateNewKeyRingTask = new GenerateKeyRingTask(userName, userMail, userPassword, algorithm, keySize);
        Future<Boolean> result = executor.submit(generateNewKeyRingTask);
        try {
            return result.get();
        } catch (InterruptedException | ExecutionException ex) {
            return false;
        }
    }

    class GenerateKeyRingTask implements Callable<Boolean> {

        String userName;
        String userMail;
        String userPassword;
        String algorithm;
        int keySize;

        public GenerateKeyRingTask(String userName, String userMail, String userPassword, String algorithm, int keySize) {
            this.userName = userName;
            this.userMail = userMail;
            this.userPassword = userPassword;
            this.algorithm = algorithm;
            this.keySize = keySize;
        }

        @Override
        public Boolean call() throws Exception {
            return PGPAsymmetricKeyUtil.this.generateNewKeyRingTask(userName, userMail, userPassword, algorithm, keySize);
        }
    }

    public boolean generateNewKeyRingTask(String userName, String userMail, String userPassword, String algorithm, int keySize) {
        try {

            int masterKeySize = MASTER_KEY_SIZE;
            if (algorithm.equals("DSA")) {
                masterKeySize = keySize;
            }
            KeyPair masterKeyPair = generateNewKeyPair(MASTER_KEY_ALGORITHM, masterKeySize, SECURITY_PROVIDER);

            Date currentDate = new Date();

            PGPKeyPair masterPGPKeyPair = new JcaPGPKeyPair(algorithms.get(MASTER_KEY_ALGORITHM), masterKeyPair, currentDate);

            PGPDigestCalculator sha1Hash = new JcaPGPDigestCalculatorProviderBuilder().build().get(PGPUtil.SHA1);

            JcaPGPContentSignerBuilder signerBuilder = new JcaPGPContentSignerBuilder(masterPGPKeyPair.getPublicKey().getAlgorithm(), PGPUtil.SHA384);

            JcePBESecretKeyEncryptorBuilder secretKeyEncBuilder = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Hash);
            PBESecretKeyEncryptor keyEncryptor = secretKeyEncBuilder.setProvider(SECURITY_PROVIDER).build(userPassword.toCharArray());

            String userInfo = String.format("%s <%s>", userName, userMail);

            PGPKeyRingGenerator pgpKeyRingGenerator = new PGPKeyRingGenerator(
                    PGPSignature.POSITIVE_CERTIFICATION, masterPGPKeyPair, userInfo, sha1Hash, null, null, signerBuilder, keyEncryptor);

            if (!algorithm.equals("DSA")) {
                KeyPair newKeyPair = generateNewKeyPair(algorithm, keySize, SECURITY_PROVIDER);
                PGPKeyPair newPGPKeyPair = new JcaPGPKeyPair(algorithms.get(algorithm), newKeyPair, currentDate);
                pgpKeyRingGenerator.addSubKey(newPGPKeyPair);

            }
            PGPSecretKeyRing pgpSecretKeyRing = pgpKeyRingGenerator.generateSecretKeyRing();
            addSCKeyRingToSCRingCollection(pgpSecretKeyRing);
            try {
                PGPKeyExporter.exportKeySCRingCollection(pgpSecretKeyRingCollection, SC_KEY_RING_COLLECTION);
            } catch (IOException ex) {
                return false;
            }

            return true;

        } catch (NoSuchAlgorithmException | NoSuchProviderException | PGPException e) {
            return false;
        }
    }

    public PGPPublicKeyRing getPUKeyRingFromPUKeyRingCollection(long publicKeyID) {
        Iterator<PGPPublicKeyRing> pgpPublicKeyRingIterator = pgpPublicKeyRingCollection.getKeyRings();
        while (pgpPublicKeyRingIterator.hasNext()) {
            PGPPublicKeyRing pgpPublicKeyRing = pgpPublicKeyRingIterator.next();
            Iterator<PGPPublicKey> pgpPublicKeyIterator = pgpPublicKeyRing.iterator();
            while (pgpPublicKeyIterator.hasNext()) {
//            pgpPublicKeyIterator.next();
                PGPPublicKey pgpPublicKey = pgpPublicKeyIterator.next();

                if (pgpPublicKey.getKeyID() == publicKeyID) {
                    return pgpPublicKeyRing;
                }
            }
        }
        return null;
    }

    public PGPSecretKeyRing getSCKeyRingFromSCKeyRingCollection(long publicKeyID) {
        Iterator<PGPSecretKeyRing> pgpSecretKeyRingIterator = pgpSecretKeyRingCollection.getKeyRings();
        while (pgpSecretKeyRingIterator.hasNext()) {
            PGPSecretKeyRing pgpSecretKeyRing = pgpSecretKeyRingIterator.next();
            Iterator<PGPSecretKey> pgpSecretKeyIterator = pgpSecretKeyRing.iterator();

            while (pgpSecretKeyIterator.hasNext()) {
                //   pgpSecretKeyIterator.next();
                PGPSecretKey pgpSecretKey = pgpSecretKeyIterator.next();

                if (pgpSecretKey.getKeyID() == publicKeyID) {
                    return pgpSecretKeyRing;
                }
            }
        }
        return null;
    }

    public boolean deleteSCKeyRing(long publicID, String password) {
        try {
            PGPSecretKeyRing pgpSecretKeyRing = getSCKeyRingFromSCKeyRingCollection(publicID);
            if (pgpSecretKeyRing == null) {
                return false;
            }
            PGPSecretKey pGPSecretKey = getSCKeyFromSCRing(pgpSecretKeyRing);
            pgpSecretKeyRing.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                    .setProvider(SECURITY_PROVIDER).build(password.toCharArray()));
            pgpSecretKeyRingCollection = PGPSecretKeyRingCollection.removeSecretKeyRing(pgpSecretKeyRingCollection, pgpSecretKeyRing);
            return true;
        } catch (PGPException ex) {
            return false;
        }
    }

    public boolean deletePUKeyRing(long publicID) {
        PGPPublicKeyRing pgpPublicKeyRing = getPUKeyRingFromPUKeyRingCollection(publicID);
        if (pgpPublicKeyRing == null) {
            return false;
        }
        pgpPublicKeyRingCollection = PGPPublicKeyRingCollection.removePublicKeyRing(pgpPublicKeyRingCollection, pgpPublicKeyRing);
        return true;
    }

    public static PGPPublicKey getPUKeyFromPURing(PGPPublicKeyRing pgpPublicKeyRing) {
        Iterator<PGPPublicKey> pgpPublicKeyIterator = pgpPublicKeyRing.iterator();
        PGPPublicKey masterKey = pgpPublicKeyIterator.next();
        if (pgpPublicKeyIterator.hasNext()) {
            return pgpPublicKeyIterator.next();
        } else {
            return masterKey;
        }
    }

    public static PGPSecretKey getSCKeyFromSCRing(PGPSecretKeyRing pgpSecretKeyRing) {
        Iterator<PGPSecretKey> pgpSecretKeyIterator = pgpSecretKeyRing.iterator();
        PGPSecretKey masterKey = pgpSecretKeyIterator.next();
        if (pgpSecretKeyIterator.hasNext()) {
            return pgpSecretKeyIterator.next();
        } else {
            return masterKey;
        }
    }

    public ArrayList<PGPPublicKeyRing> getPublicKeyRings() {
        Iterator<PGPPublicKeyRing> keyRingIterator = pgpPublicKeyRingCollection.getKeyRings();
        ArrayList<PGPPublicKeyRing> pgpPublicKeys = new ArrayList<>();
        while (keyRingIterator.hasNext()) {
            pgpPublicKeys.add(keyRingIterator.next());
        }
        return pgpPublicKeys;
    }

    public ArrayList<PGPSecretKeyRing> getSecretKeyRings() {
        Iterator<PGPSecretKeyRing> keyRingIterator = pgpSecretKeyRingCollection.getKeyRings();
        ArrayList<PGPSecretKeyRing> pgpSecretKeys = new ArrayList<>();
        while (keyRingIterator.hasNext()) {
            pgpSecretKeys.add(keyRingIterator.next());
        }
        return pgpSecretKeys;
    }

    public boolean importKeyToPUKeyRingCollection(String path) {
        try {
            PGPPublicKeyRing pgpPublicKeyRing = PGPKeyImporter.importPUKeyRIng(path);
            addPUKeyRingToPURingCollection(pgpPublicKeyRing);
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    public boolean importKeyToSCKeyRingCollection(String path) {
        try {
            PGPSecretKeyRing pgpSecretKeyRing = PGPKeyImporter.importSCKeyRing(path);
            addSCKeyRingToSCRingCollection(pgpSecretKeyRing);
            return true;
        } catch (IOException | PGPException ex) {
            return false;
        }
    }

    public boolean exportKeyFromSCKeyRingCollection(long keyID, String path) {
        try {
            PGPSecretKeyRing pgpSecretKeyRing = getSCKeyRingFromSCKeyRingCollection(keyID);
            if (pgpSecretKeyRing == null) {
                return false;
            }
            PGPKeyExporter.exportSCKey(pgpSecretKeyRing, path);
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    public boolean exportKeyFromPURingCollection(long keyID, String path) {
        try {
            PGPPublicKeyRing pgpPublicKeyRing = getPUKeyRingFromPUKeyRingCollection(keyID);
            if (pgpPublicKeyRing == null) {
                return false;
            }
            PGPKeyExporter.exportPUKey(pgpPublicKeyRing, path);
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    public boolean exporPUtKeyFromSCKeyRingCollection(long keyID, String path) {
        try {
            PGPSecretKeyRing pgpSecretKeyRing = getSCKeyRingFromSCKeyRingCollection(keyID);
            if (pgpSecretKeyRing == null) {
                return false;
            }
            List<PGPPublicKey> publicKeys = new ArrayList<>();
            pgpSecretKeyRing.getPublicKeys().forEachRemaining(publicKeys::add);

            Iterator<PGPPublicKey> itextrapublic = pgpSecretKeyRing.getExtraPublicKeys();
            while (itextrapublic.hasNext()) {
                PGPPublicKey pub = itextrapublic.next();
                publicKeys.add(pub);
            }

            PGPPublicKeyRing pgpPublicKeyRing = new PGPPublicKeyRing(publicKeys);

            PGPKeyExporter.exportPUKey(pgpPublicKeyRing, path);
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    public void savePUKeyRingCollection() {
        try {
            PGPKeyExporter.exportKeyPURingCollection(pgpPublicKeyRingCollection, PU_KEY_RING_COLLECTION);
        } catch (IOException ex) {
            Logger.getLogger(PGPAsymmetricKeyUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void saveSCKeyRingCollection() {
        try {
            PGPKeyExporter.exportKeySCRingCollection(pgpSecretKeyRingCollection, SC_KEY_RING_COLLECTION);
        } catch (IOException ex) {
            Logger.getLogger(PGPAsymmetricKeyUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
