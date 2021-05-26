package om160246d;

import static javax.swing.JOptionPane.showMessageDialog;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;



public class Main {

	public static void main(String[] args) {
		String name1 = "Nikola Vucenovic <nikolavucenovic97@gmail.com>";
		String password1 = "Sifra123";
		String name2 = "Milo Tomasevic <milo@gmail.com>";
		String password2 = "Sifra123";
		try {
			PGPKeyRingGenerator pgpKeyRingGenerator1 = PGPKeyTools.createPGPKeyRingGenerator(PGPKeyTools.generateDsaKeyPair(1024), PGPKeyTools.generateElGamalKeyPair(1024), name1, password1.toCharArray());
			PGPKeyRingGenerator pgpKeyRingGenerator2 = PGPKeyTools.createPGPKeyRingGenerator(PGPKeyTools.generateDsaKeyPair(1024), PGPKeyTools.generateElGamalKeyPair(1024), name2, password2.toCharArray());

			PGPKeyTools.addPublicKey(pgpKeyRingGenerator1);
			PGPKeyTools.addSecretKey(pgpKeyRingGenerator1);
		//	PGPKeyTools.exportPublicKey(pgpKeyRingGenerator2);
		//	File inputFileName = new File("C:\\Users\\Mihajlo\\Desktop\\send.txt");
		//	File outputFileName = new File("C:\\Users\\Mihajlo\\Desktop\\output.txt.gpg");
		//	PGPCryptoTools.signAndEncrypt(outputFileName, inputFileName, publicKeyFile, privateKeyFile, true, true, password.toCharArray(),true, false, false);
			
		//	File inputFileName = new File("C:\\Users\\Mihajlo\\Desktop\\aa.txt.sig");
		//	File outputFileName = new File("C:\\Users\\Mihajlo\\Desktop\\izlaz.txt");
		//	PGPCryptoTools.decryptAndVerify(inputFileName,outputFileName,privateKeyFile,publicKeyFile,"Sifra123".toCharArray());
		//	PGPCryptoTools.decryptFile(inputFileName, privateKeyFile, "Sifra123".toCharArray(), outputFileName);
			
		/*	Iterator<PGPSecretKeyRing> iter = PGPCryptoTools.getPrivateKeys(new FileInputStream(privateKeyFile)).getKeyRings();
            while (iter.hasNext()) {
                    PGPSecretKeyRing keyRing = iter.next();

                    Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
                    
                    while (keyIter.hasNext()) {
                            PGPSecretKey key = keyIter.next();
                            key.getUserIDs().next();
                            System.out.println(Integer.toHexString((int) key.getKeyID()) + " ");
                    }
            }
		*/
			//PGPKeyTools.importPublicKey(new File("C:\\Users\\Mihajlo\\Desktop\\export.asc"));
			/*PGPPublicKeyRingCollection pgpPub = PGPKeyTools.getPublicKeysCollection();
			
		
            Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
          
            while (keyRingIter.hasNext()) {
                    PGPPublicKeyRing keyRing = keyRingIter.next();
                    
                    Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
              //    while (keyIter.hasNext()) {
                            PGPPublicKey key = keyIter.next();
                            
                            System.out.println(Integer.toHexString((int) key.getKeyID()) + " " + new String(key.getRawUserIDs().next(),StandardCharsets.UTF_8));
              //      }
                            if(new String(key.getRawUserIDs().next(),StandardCharsets.UTF_8).equals("Mihajlo Ogrizovic <mihajlo.ogrizovic@gmail.com>")) {
                            	//PGPKeyTools.exportPublicKey(keyRing, new File("C:\\Users\\Mihajlo\\Desktop\\export.asc"));
                            	//PGPKeyTools.removePublicKey(keyRing);
                            }
            }
         
       
            
          PGPKeyTools.savePublicKeysToFile(); */
			//PGPKeyTools.addSecretKey(pgpKeyRingGenerator1);
			 Iterator<PGPSecretKeyRing> keyRingIter = PGPKeyTools.getSecretKeysCollection().getKeyRings();
	          
	            while (keyRingIter.hasNext()) {
	                    PGPSecretKeyRing keyRing = keyRingIter.next();
	                    
	                    Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
	              //    while (keyIter.hasNext()) {
	                    		PGPSecretKey key = keyIter.next();
	                    		PGPPrivateKey privateKey = key.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("Sifra123".toCharArray()));
	                    		PGPPublicKey  publicKey = key.getPublicKey();
	                            System.out.println(Integer.toHexString((int) key.getKeyID()) + " " + key.getUserIDs().next());
	                 
	                         //   }
	                         /*   if(new String(key.getRawUserIDs().next(),StandardCharsets.UTF_8).equals("Mihajlo Ogrizovic <mihajlo.ogrizovic@gmail.com>")) {
	                            	//PGPKeyTools.exportPublicKey(keyRing, new File("C:\\Users\\Mihajlo\\Desktop\\export.asc"));
	                            	//PGPKeyTools.removePublicKey(keyRing);
	                            }*/
	            }
			
	            
	            Iterator<PGPPublicKeyRing> keyRingIter2 = PGPKeyTools.getPublicKeysCollection().getKeyRings();
	            
	            while (keyRingIter2.hasNext()) {
	                    PGPPublicKeyRing keyRing = keyRingIter2.next();
	                    
	                    Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
	              //    while (keyIter.hasNext()) {
	                            PGPPublicKey key = keyIter.next();
	                            
	                            System.out.println(Integer.toHexString((int) key.getKeyID()) + " " + new String(key.getRawUserIDs().next(),StandardCharsets.UTF_8));
	              //      }
	                            if(new String(key.getRawUserIDs().next(),StandardCharsets.UTF_8).equals("Mihajlo Ogrizovic <mihajlo.ogrizovic@gmail.com>")) {
	                            	//PGPKeyTools.exportPublicKey(keyRing, new File("C:\\Users\\Mihajlo\\Desktop\\export.asc"));
	                            	//PGPKeyTools.removePublicKey(keyRing);
	                            }
	            }    
			PGPKeyTools.saveSecretKeysToFile();
			PGPKeyTools.savePublicKeysToFile();
			showMessageDialog(null, "Finished");
			//System.out.println("Finished!");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
