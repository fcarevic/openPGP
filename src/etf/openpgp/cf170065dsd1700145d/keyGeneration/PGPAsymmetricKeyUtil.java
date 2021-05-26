package etf.openpgp.cf170065dsd1700145d.keyGeneration;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;

public class PGPAsymmetricKeyUtil {

    //My public-private keys collections
    private PGPSecretKeyRingCollection pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(new ArrayList<>());
    //Receivers public keys collections
    private PGPPublicKeyRingCollection pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(new ArrayList<>());


    private final Map<String, Integer> algorithms = Map.of(
            "DSA", PGPPublicKey.DSA,
            "ELGAMAL", PGPPublicKey.ELGAMAL_ENCRYPT
    );


    final static String SECURITY_PROVIDER = "BC";
    final static String MASTER_KEY_ALGORITHM = "DSA";
    final static int MASTER_KEY_SIZE = 1024;

    public PGPAsymmetricKeyUtil() throws PGPException, IOException {
    }

    private KeyPair generateNewKeyPair(String algorithm, int keySize, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    private void addSCKeyRingToSCRingCollection(PGPSecretKeyRing pgpSecretKeyRing) {
        if (pgpSecretKeyRing == null) return;
        PGPSecretKeyRingCollection.addSecretKeyRing(pgpSecretKeyRingCollection, pgpSecretKeyRing);
    }

    public boolean generateNewKeyRing(String userName, String userMail, String userPassword, String algorithm, int keySize) {
        try {
            KeyPair newKeyPair = generateNewKeyPair(algorithm, keySize, SECURITY_PROVIDER);
            KeyPair masterKeyPair = generateNewKeyPair(MASTER_KEY_ALGORITHM, MASTER_KEY_SIZE, SECURITY_PROVIDER);

            Date currentDate = new Date();

            PGPKeyPair newPGPKeyPair = new JcaPGPKeyPair(algorithms.get(algorithm), newKeyPair, currentDate);
            PGPKeyPair masterPGPKeyPair = new JcaPGPKeyPair(algorithms.get(MASTER_KEY_ALGORITHM), masterKeyPair, currentDate);


            PGPDigestCalculator sha1Hash = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

            JcaPGPContentSignerBuilder signerBuilder = new JcaPGPContentSignerBuilder(masterPGPKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1);

            JcePBESecretKeyEncryptorBuilder secretKeyEncBuilder = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Hash);
            PBESecretKeyEncryptor keyEncryptor = secretKeyEncBuilder.setProvider(SECURITY_PROVIDER).build(userPassword.toCharArray());

            String userInfo = String.format("%s-%s", userName, userMail);

            PGPKeyRingGenerator pgpKeyRingGenerator = new PGPKeyRingGenerator(
                    PGPSignature.POSITIVE_CERTIFICATION, masterPGPKeyPair, userInfo, sha1Hash, null, null, signerBuilder, keyEncryptor);

            pgpKeyRingGenerator.addSubKey(newPGPKeyPair);

            PGPSecretKeyRing pgpSecretKeyRing = pgpKeyRingGenerator.generateSecretKeyRing();
            addSCKeyRingToSCRingCollection(pgpSecretKeyRing);

            return true;

        } catch (NoSuchAlgorithmException | NoSuchProviderException | PGPException e) {
            e.printStackTrace();
            return false;
        }

    }

    public PGPPublicKeyRing getPUKeyRingFromPUKeyRingCollection(long publicKeyID) {
        Iterator<PGPPublicKeyRing> pgpPublicKeyRingIterator = pgpPublicKeyRingCollection.getKeyRings();
        while (pgpPublicKeyRingIterator.hasNext()) {
            PGPPublicKeyRing pgpPublicKeyRing = pgpPublicKeyRingIterator.next();
            Iterator<PGPPublicKey> pgpPublicKeyIterator = pgpPublicKeyRing.iterator();

            pgpPublicKeyIterator.next();
            PGPPublicKey pgpPublicKey = pgpPublicKeyIterator.next();

            if (pgpPublicKey.getKeyID() == publicKeyID) {
                return pgpPublicKeyRing;
            }
        }
        return null;
    }

    public PGPSecretKeyRing getSCKeyRingFromSCKeyRingCollection(long publicKeyID) {
        Iterator<PGPSecretKeyRing> pgpSecretKeyRingIterator = pgpSecretKeyRingCollection.getKeyRings();
        while (pgpSecretKeyRingIterator.hasNext()) {
            PGPSecretKeyRing pgpSecretKeyRing = pgpSecretKeyRingIterator.next();
            Iterator<PGPSecretKey> pgpSecretKeyIterator = pgpSecretKeyRing.iterator();

            pgpSecretKeyIterator.next();
            PGPSecretKey pgpSecretKey = pgpSecretKeyIterator.next();

            if (pgpSecretKey.getKeyID() == publicKeyID) {
                return pgpSecretKeyRing;
            }
        }
        return null;
    }

    public boolean deleteSCKeyRing(long publicID) throws PGPException {
        PGPSecretKeyRing pgpSecretKeyRing = getSCKeyRingFromSCKeyRingCollection(publicID);
        if (pgpSecretKeyRing == null) return false;
        pgpSecretKeyRingCollection = PGPSecretKeyRingCollection.removeSecretKeyRing(pgpSecretKeyRingCollection, pgpSecretKeyRing);
        return true;
    }

    public boolean deletePUKeyRing(long publicID) throws PGPException {
        PGPPublicKeyRing pgpPublicKeyRing = getPUKeyRingFromPUKeyRingCollection(publicID);
        if (pgpPublicKeyRing == null) return false;
        pgpPublicKeyRingCollection = PGPPublicKeyRingCollection.removePublicKeyRing(pgpPublicKeyRingCollection, pgpPublicKeyRing);
        return true;
    }


    public PGPPublicKey getPUKeyFromPURing(PGPPublicKeyRing pgpPublicKeyRing) {
        Iterator<PGPPublicKey> pgpPublicKeyIterator = pgpPublicKeyRing.iterator();
        pgpPublicKeyIterator.next();
        return pgpPublicKeyIterator.next();
    }

    public PGPSecretKey getSCKeyFromSCRing(PGPSecretKeyRing pgpSecretKeyRing) {
        Iterator<PGPSecretKey> pgpSecretKeyIterator = pgpSecretKeyRing.iterator();
        PGPSecretKey pgpSecretKey = pgpSecretKeyIterator.next();
        return pgpSecretKeyIterator.next();
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

}
