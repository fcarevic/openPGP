/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.cf170065dsd170145d.keyGeneration;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

/**
 *
 * @author Dušan
 */
public class PGPKeyInfo {

    private final String name;
    private final String email;
    private final String publicKeyId;
    private final String timeStamp;
    private final String algorithm;

    /**
     *
     * @param name
     * @param email
     * @param publicKeyId
     * @param dateCreation
     * @param algorithm
     */
    public PGPKeyInfo(String name, String email, String publicKeyId, String dateCreation, String algorithm) {
        this.name = name;
        this.email = email;
        this.publicKeyId = publicKeyId;
        this.timeStamp = dateCreation;
        this.algorithm = algorithm;
    }

    /**
     *
     * @param pgpPublicKeyRing
     * @return
     */
    public static List<PGPKeyInfo> getPGPPublicKeyRingPGPKeyInfo(PGPPublicKeyRing pgpPublicKeyRing) {
        List<PGPKeyInfo> pgpKeyInfos = new ArrayList<>();
        Iterator<PGPPublicKey> iterator = pgpPublicKeyRing.iterator();
        while (iterator.hasNext()) {
            pgpKeyInfos.add(new PGPKeyInfo(iterator.next(), pgpPublicKeyRing.getPublicKey().getUserIDs().next()));
        }
        return pgpKeyInfos;
    }

    /**
     *
     * @param pgpSecretKeyRing
     * @return
     */
    public static List<PGPKeyInfo> getPGPSecretKeyRingPGPKeyInfo(PGPSecretKeyRing pgpSecretKeyRing) {
        List<PGPKeyInfo> pgpKeyInfos = new ArrayList<>();
        Iterator<PGPSecretKey> iterator = pgpSecretKeyRing.iterator();
        while (iterator.hasNext()) {
            pgpKeyInfos.add(new PGPKeyInfo(iterator.next(), pgpSecretKeyRing.getPublicKey().getUserIDs().next()));
        }
        return pgpKeyInfos;
    }

    /**
     *
     * @param pgpPublicKey public key from which object bill be built
     * @param userInfo information of key owner
     */
    public PGPKeyInfo(PGPPublicKey pgpPublicKey, String userInfo) {
        publicKeyId = String.valueOf(pgpPublicKey.getKeyID());
        timeStamp = String.valueOf(pgpPublicKey.getCreationTime());
        algorithm = PGPAsymmetricKeyUtil.getAlgorithmByID(pgpPublicKey.getAlgorithm());

        String[] split = userInfo.split("<");
        name = split[0];

        if (split.length > 1) {
            email = split[1].substring(0, split[1].length() - 1);
        } else {
            email = "undefined";
        }
    }

    /**
     *
     * @param pgpSecretKey secret key from which object bill be built
     * @param userInfo information of key owner
     */
    public PGPKeyInfo(PGPSecretKey pgpSecretKey, String userInfo) {

        publicKeyId = String.valueOf(pgpSecretKey.getKeyID());
        timeStamp = String.valueOf(pgpSecretKey.getPublicKey().getCreationTime());
        algorithm = PGPAsymmetricKeyUtil.getAlgorithmByID(pgpSecretKey.getPublicKey().getAlgorithm());

        String[] split = userInfo.split("<");
        name = split[0];
        if (split.length > 1) {
            email = split[1].substring(0, split[1].length() - 1);
        } else {
            email = "undefined";
        }
    }

    /**
     *
     * @return name
     */
    public String getName() {
        return name;
    }

    /**
     *
     * @return email
     */
    public String getEmail() {
        return email;
    }

    /**
     *
     * @return key id
     */
    public String getPublicKeyId() {
        return publicKeyId;
    }

    /**
     *
     * @return creation key time
     */
    public String getTimeStamp() {
        return timeStamp;
    }

    /**
     *
     * @return key algorithm generation
     */
    public String getAlgorithm() {
        return algorithm;
    }

}
