/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.cf170065dsd170145d.keyGeneration;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

/**
 *
 * @author Dušan
 */
public class PGPKeyInfo {

    private String name;
    private String email;
    private String publicKeyId;
    private String timeStamp;
    private String algorithm;

    public PGPKeyInfo(String name, String email, String publicKeyId, String dateCreation, String algorithm) {
        this.name = name;
        this.email = email;
        this.publicKeyId = publicKeyId;
        this.timeStamp = dateCreation;
        this.algorithm = algorithm;
    }

    public PGPKeyInfo(PGPPublicKeyRing pgpPublicKeyRing) {
        PGPPublicKey pgpPublicKey = PGPAsymmetricKeyUtil.getPUKeyFromPURing(pgpPublicKeyRing);
        publicKeyId = String.valueOf(pgpPublicKey.getKeyID());
        timeStamp = String.valueOf(pgpPublicKey.getCreationTime());
        algorithm = PGPAsymmetricKeyUtil.getAlgorithmByID(pgpPublicKey.getAlgorithm());

        String userInfo = pgpPublicKeyRing.getPublicKey().getUserIDs().next();

        String[] split = userInfo.split("<");
        name = split[0];
        email="undefined";
        if(split.length>1)
        email = split[1].substring(0, split[1].length() - 1);
    }

    public PGPKeyInfo(PGPSecretKeyRing pgpSecretKeyRing) {
        PGPSecretKey pGPSecretKey = PGPAsymmetricKeyUtil.getSCKeyFromSCRing(pgpSecretKeyRing);
        publicKeyId = String.valueOf(pGPSecretKey.getKeyID());
        timeStamp = String.valueOf(pGPSecretKey.getPublicKey().getCreationTime());
        algorithm = PGPAsymmetricKeyUtil.getAlgorithmByID(pGPSecretKey.getPublicKey().getAlgorithm());

        String userInfo = pgpSecretKeyRing.getPublicKey().getUserIDs().next();

        String[] split = userInfo.split("<");
        name = split[0];
email="undefined";
        if(split.length>1)
        email = split[1].substring(0, split[1].length() - 1);
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public String getPublicKeyId() {
        return publicKeyId;
    }

    public String getTimeStamp() {
        return timeStamp;
    }

    public String getAlgorithm() {
        return algorithm;
    }

}
