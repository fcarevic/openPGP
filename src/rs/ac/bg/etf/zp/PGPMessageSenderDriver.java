package rs.ac.bg.etf.zp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
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

import om160246d.PGPKeyTools;

public class PGPMessageSenderDriver {

	private boolean requiresSignature;
	private boolean requiresCompression;
	private boolean requiresEncryption;
	private boolean requiresRadix64;
	private byte[] data;
	private PGPPrivateKey signingKey;
	private int signingAlgorithm;
	private PGPPublicKey encryptionKey;
	private int encryptionAlgorithm;
	private int compressionAlgorithm = CompressionAlgorithmTags.ZIP;
	
	
	
	private String password;

	public void setPassword(String password) {
		this.password=password;
	}
	
	public boolean isRequiresSignature() {
		return requiresSignature;
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
	
	
	
	public void configSignature(boolean isRequired, int algorithm, PGPPrivateKey signingKey) {
		 this.requiresSignature=isRequired;
		 this.signingKey=signingKey;
		 this.signingAlgorithm=algorithm;
	}
	
	public void configEncryption(boolean isRequired, int algorithm,PGPPublicKey encryptionKey) {
		
		this.requiresEncryption=isRequired;
		this.encryptionKey=encryptionKey;
		this.encryptionAlgorithm=algorithm;
	}
	
	public void configCompression(boolean isRequired, int algorithm) {
		this.requiresCompression=isRequired;
		this.compressionAlgorithm=algorithm;
	}
	
	public byte[] encrypt() throws PGPException, IOException {
		byte [] processedData= this.data;
		if(requiresSignature) 
			processedData=PGPServicesUtil.sign(processedData, signingKey, signingAlgorithm);
		if(requiresCompression)
			processedData = PGPServicesUtil.compress(processedData, compressionAlgorithm);
		if(requiresEncryption)
			processedData=PGPServicesUtil.encrypt(processedData, encryptionKey, encryptionAlgorithm);
		if(requiresRadix64)
			processedData= PGPServicesUtil.encodeRadix64(processedData);
		return processedData;
	}
	
	public byte[] decrypt() throws Exception {
		InputStream in = new ByteArrayInputStream(data);
		in=PGPServicesUtil.decodeRadix64(in);
		in= PGPServicesUtil.decrypt(in, password.toCharArray());
		in=PGPServicesUtil.decompress(in);
		byte savedData[] = in.readAllBytes();
		byte[] cloned = savedData.clone();
//		cloned[456]=12;
		PGPServicesUtil.verifySignature(new ByteArrayInputStream(cloned)); //puca exception ako nije zadovojeno
		return savedData;
	}
	
	
	
	
	public void processMessage(String inputFile, String outputFile, boolean encrypt) {
		try {
			this.data = IOUtil.readFromFile(inputFile);
			byte[] processedData= encrypt? encrypt(): decrypt();
			IOUtil.writeToFile(outputFile, processedData);
		} catch ( Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			ErrorReportUtil.reportError(e);
		}
		
	}
	
	public static void main(String [] args) {
		
		String name1 = "Nikola Vucenovic <nikolavucenovic97@gmail.com>";
		String password1 = "Sifra123";
		String name2 = "Milo Tomasevic <milo@gmail.com>";
		String password2 = "Sifra123";
		
		
		PGPKeyRingGenerator pgpKeyRingGenerator1;
		try {
			pgpKeyRingGenerator1 = PGPKeyTools.createPGPKeyRingGenerator(PGPKeyTools.generateDsaKeyPair(1024), PGPKeyTools.generateElGamalKeyPair(1024), name1, password1.toCharArray());
		
			PGPKeyRingGenerator pgpKeyRingGenerator2 = PGPKeyTools.createPGPKeyRingGenerator(PGPKeyTools.generateDsaKeyPair(1024), PGPKeyTools.generateElGamalKeyPair(1024), name2, password2.toCharArray());

			PGPKeyTools.addPublicKey(pgpKeyRingGenerator1);
			PGPKeyTools.addSecretKey(pgpKeyRingGenerator1);
			
			int alg = PGPEncryptedData.IDEA;
			
			PGPMessageSenderDriver ms = new PGPMessageSenderDriver();
			PGPPublicKeyRingCollection publicKeyRingColl = PGPKeyTools.getPublicKeysCollection();
			
			PGPPublicKeyRing pbRing=publicKeyRingColl.getKeyRings().next();
			Iterator<PGPPublicKey> iter = pbRing.getPublicKeys();
			iter.next();
			PGPPublicKey publicKey = iter.next();
			ms.setRequiresCompression(true);
			ms.setRequiresRadix64(true);
			ms.configEncryption(true,  PGPEncryptedData.IDEA, publicKey);
			
			PGPSecretKeyRingCollection privCol = PGPKeyTools.getSecretKeysCollection();
			Iterator<PGPSecretKeyRing> privIter = privCol.getKeyRings();
			PGPSecretKeyRing privateKeyRing = privIter.next();
	            //TODO DOHVATANJE RINGA KLJUCEVA
			PGPPrivateKey privateKey=null; 
			int signAlg=1;
	            if (privateKeyRing != null)
	            {
	            	java.util.Iterator<PGPSecretKey> iterPriv = privateKeyRing.getSecretKeys();
	            	PGPSecretKey masterKey = iterPriv.next();
	            	PGPSecretKey secretKey = iterPriv.next();
	            	System.out.println(masterKey.isSigningKey());
	            	signAlg=masterKey.getPublicKey().getAlgorithm();
	            	
	        	privateKey = masterKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
							.setProvider("BC").build(password1.toCharArray()));
	            }
			
			
			ms.configSignature(true, signAlg, privateKey);
			
			
			ms.processMessage("srpski.txt", "srpski-encrypted.txt", true);
			
			ms.setPassword("Sifra123");
			ms.processMessage("srpski-encrypted.txt", "srpski-decrypted.txt", false);
			System.out.println("Finished sending");
			
			
			
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	

		
	}
	

	

}
