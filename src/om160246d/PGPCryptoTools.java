package om160246d;

import static javax.swing.JOptionPane.showMessageDialog;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jcajce.provider.symmetric.CAST5;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;




public final class PGPCryptoTools {

		
        static {
                if (Security.getProvider("BC") == null) {
                        Security.addProvider(new BouncyCastleProvider());
                }
              
        }

        private PGPCryptoTools() {

        }

        
       
        
        
        private static PGPSecretKey readSecretKey(long id) throws IOException, PGPException {
                PGPSecretKeyRingCollection pgpSec = PGPKeyTools.getSecretKeysCollection();
                PGPSecretKey secKey = null;

                Iterator<PGPSecretKeyRing> iter = pgpSec.getKeyRings();
                while (iter.hasNext() && secKey == null) {
                        PGPSecretKeyRing keyRing = iter.next();

                        Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
                        while (keyIter.hasNext()) {
                                PGPSecretKey key = keyIter.next();
                                if (key.isSigningKey() && (key.getKeyID() == id)) {
                                        secKey = key;
                                        break;
                                }
                        }
                }

                if (secKey != null) {
                        return secKey;
                }
                else {
                	showMessageDialog(null,"Can't find signing key in key ring.");
                        throw new IllegalArgumentException("Can't find signing key in key ring.");
                }
        }


        private static final PGPPublicKey readPublicKey(long id) throws IOException, PGPException {
                PGPPublicKeyRingCollection pgpPub = PGPKeyTools.getPublicKeysCollection();
                PGPPublicKey pubKey = null;

                Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
                while (keyRingIter.hasNext() && pubKey == null) {
                        PGPPublicKeyRing keyRing = keyRingIter.next();

                        Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
                        while (keyIter.hasNext()) {
                                PGPPublicKey key = keyIter.next();
                                if (key.isEncryptionKey() && (key.getKeyID() == id)) {
                                        pubKey = key;
                                        break;
                                }
                        }
                }

                if (pubKey != null) {
                        return pubKey;
                }
                else {
                	showMessageDialog(null,"Can't find encryption key in key ring.");
                        throw new IllegalArgumentException("Can't find encryption key in key ring.");
                }
        }
        
        public static void signAndEncrypt(File outputFileName, File inputFileName, boolean asciiArmor, boolean integrityCheck, char[] passphrase,  boolean withSignature, boolean withEncryption, boolean withCompression, int alghortim, long secreteKeyId, long publicKeyId) throws IOException, PGPException, NoSuchProviderException {
        	FileOutputStream fileO = new FileOutputStream(outputFileName);
        	int alg = 0;
        	if(alghortim == 0) {
        		alg = PGPEncryptedData.TRIPLE_DES;
        	}
        	else if (alghortim == 1){
        		alg = PGPEncryptedData.IDEA;
        	}
        	encryptFile(fileO, inputFileName, readPublicKey(publicKeyId), readSecretKey(secreteKeyId), asciiArmor, integrityCheck, passphrase, withSignature, withEncryption, withCompression, alg);
        	fileO.close();
        }
        
        private static void encryptFile(OutputStream out, File file, PGPPublicKey encKey, PGPSecretKey pgpSec, boolean armor, boolean withIntegrityCheck, char[] pass, boolean withSignature, boolean withEncryption, boolean withCompression, int alghoritm) throws IOException, NoSuchProviderException {
            if (armor) {
                out = new ArmoredOutputStream(out);
            }

            try {
            	OutputStream encryptedOut = null;
            	PGPEncryptedDataGenerator encGen = null;
            	if(withEncryption) {
                 encGen =
                        new PGPEncryptedDataGenerator(
                        new JcePGPDataEncryptorBuilder(alghoritm).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(
                        new SecureRandom())
                        .setProvider("BC"));
                encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
                encryptedOut = encGen.open(out, new byte[1 << 16]);
            	}
            	else encryptedOut = out;
            	
                int compressedDataInt = PGPCompressedData.UNCOMPRESSED;
                PGPCompressedDataGenerator comData = null;
                OutputStream compressedData = null;
                if(withCompression) {
                	compressedDataInt = PGPCompressedData.ZIP;
                	
                }
                comData = new PGPCompressedDataGenerator(compressedDataInt);
            	compressedData = comData.open(encryptedOut);

                //OutputStream compressedData = encryptedOut;
                PGPSignatureGenerator sGen = null;
                if(withSignature) {
                PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(
                        new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
                 sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(
                        pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));
                sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
                Iterator<String> it = pgpSec.getPublicKey().getUserIDs();
                if (it.hasNext()) {
                    PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
                    spGen.setSignerUserID(false, (String) it.next());
                    sGen.setHashedSubpackets(spGen.generate());
                }
                //BCPGOutputStream bOut = new BCPGOutputStream(compressedData);
                sGen.generateOnePassVersion(false).encode(compressedData); // bOut
                }
               
                PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
                OutputStream lOut = lGen.open(compressedData, PGPLiteralData.BINARY, file.getName(), new Date(),
                                              new byte[1 << 16]); //bOut
                FileInputStream fIn = new FileInputStream(file);
                int ch;

                while ((ch = fIn.read()) >= 0) {
                    lOut.write(ch);
                    if(withSignature)
                    sGen.update((byte) ch);
                }

              
                fIn.close();
                lOut.close();
                lGen.close();
                if(withSignature)
                sGen.generate().encode(compressedData);

                //bOut.close();
                
                compressedData.close();
                if(comData != null)
                comData.close();
                encryptedOut.close();
                if(encGen != null)
                encGen.close();

                if (armor) {
                    out.close();
                }
            } catch (PGPException e) {
                System.out.println(e);
                if (e.getUnderlyingException() != null) {
                    e.getUnderlyingException().printStackTrace();
                }
            }  
          
        
        }
        
        
       static public void decryptAndVerify(File inputFile, File outputFile,  char[] passwd) throws Exception {
    		decryptAndVerifyFile(new FileInputStream(inputFile), new FileOutputStream(
    				outputFile),  passwd);
    	}

       /*static private void decryptAndVerifyFile(InputStream in, OutputStream out, File keyFileName, File publicKeyFile, char[] passwd) throws Exception {
    		BufferedOutputStream bOut = new BufferedOutputStream(out);
    		InputStream unc = decryptAndVerifyFile(new BufferedInputStream(in), bOut, keyFileName, publicKeyFile, passwd);
    		int ch;
    		while ((ch = unc.read()) >= 0) {
    			bOut.write(ch);
    		}
    		bOut.close();
    	}*/

       static public boolean isDecrypted(File inputFile) throws IOException {
    	InputStream is = null;
   		byte[] bytes = null; 
   		InputStream in = new FileInputStream(inputFile);
   	
   		in = PGPUtil.getDecoderStream(new BufferedInputStream(in));
   		
   		PGPObjectFactory pgpF = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
   		PGPEncryptedDataList enc = null;
   		Object o = pgpF.nextObject();
   		Object message = null;

   		boolean decrypted = false;
   		InputStream clear = null;
   		if (o instanceof PGPEncryptedDataList) {
   			enc = (PGPEncryptedDataList) o;
   			decrypted = true;
   		} else if (o instanceof PGPMarker){
   			o = pgpF.nextObject();
   			if (o instanceof PGPEncryptedDataList) {
       			enc = (PGPEncryptedDataList) o;
       			decrypted = true;
       		}
   		}
   		
   		return decrypted;
       }
       static private void decryptAndVerifyFile(InputStream in, OutputStream bOut,  char[] passwd) throws Exception {
    		InputStream is = null;
    		byte[] bytes = null; 
    		
    	
    		in = PGPUtil.getDecoderStream(new BufferedInputStream(in));
    		
    		PGPObjectFactory pgpF = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
    		PGPEncryptedDataList enc = null;
    		Object o = pgpF.nextObject();
    		Object message = null;

    		boolean decrypted = false;
    		InputStream clear = null;
    		if (o instanceof PGPEncryptedDataList) {
    			enc = (PGPEncryptedDataList) o;
    			decrypted = true;
    		} else if (o instanceof PGPMarker){
    			o = pgpF.nextObject();
    			if (o instanceof PGPEncryptedDataList) {
        			enc = (PGPEncryptedDataList) o;
        			decrypted = true;
        		}
    		}


    		PGPPrivateKey sKey = null;
    		PGPPublicKeyEncryptedData pbe = null;
    		if(decrypted) {
    		Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
    	
    		PGPSecretKeyRingCollection pgpSecretKeyRingCollection = PGPKeyTools.getSecretKeysCollection();
    		while (sKey == null && it.hasNext()) {
    			pbe = (PGPPublicKeyEncryptedData) it.next();
    			PGPSecretKey pgpSecKey = pgpSecretKeyRingCollection.getSecretKey(pbe.getKeyID());

                if (pgpSecKey != null) {
                        Provider provider = Security.getProvider("BC");  
                        sKey = pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider(provider).build()).setProvider(provider).build(passwd));
                }
    		}

    		if (sKey == null) {
    			showMessageDialog(null,"secret key for message not found.");
    			throw new IllegalArgumentException("secret key for message not found.");
    		}
    		else {
    			System.out.println("Decryption successful!");
    		}

    	    clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey)); 
    		PGPObjectFactory plainFact = new PGPObjectFactory(clear, null);
    		message = plainFact.nextObject();
    
    		}
    		else {
    		 message = o;
    		}
    		PGPObjectFactory pgpFact = null;
    		if (message instanceof PGPCompressedData) {
    			PGPCompressedData cData = (PGPCompressedData) message;
    			pgpFact = new PGPObjectFactory(new BufferedInputStream(cData.getDataStream()), null);
    			message = pgpFact.nextObject();
    			if(cData.getAlgorithm() != PGPCompressedData.UNCOMPRESSED)
    				showMessageDialog(null,"Decompression successful!");
    			System.out.println("Decompression successful!");
    		}
    	
    		boolean isSigned = false;
    		PGPOnePassSignature ops = null;
    		PGPPublicKey signerPublicKey = null;
    		if (message instanceof PGPOnePassSignatureList) {
    		
    				PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) message;
    				ops = p1.get(0);
    				long keyId = ops.getKeyID();
    				isSigned = true;
    			    
    			    PGPPublicKeyRingCollection pgpRing = PGPKeyTools.getPublicKeysCollection();   			   
    			    signerPublicKey = pgpRing.getPublicKey(keyId);
    			   
    				ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), signerPublicKey);
  
    			
    			message = pgpFact.nextObject();
    		}

    		if (message instanceof PGPLiteralData) {
    			PGPLiteralData ld = (PGPLiteralData) message;
    			
    			is = ld.getInputStream();
    			OutputStream out = new BufferedOutputStream(bOut);
    			bytes = is.readAllBytes();
    			out.write(bytes);
    			out.close();
    			if(pbe != null)
        			if (pbe.isIntegrityProtected()) {
        				if (!pbe.verify()) {
        					showMessageDialog(null,"message failed integrity check");
        					throw new PGPException("message failed integrity check");
        				}
        				else {
        					showMessageDialog(null, "Integrity checked successfully!");
        					System.out.println("Integrity checked successfully!");
        				}
        			}
    			if (isSigned) {
    				ops.update(bytes);
    				PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
    				if (!ops.verify(p3.get(0))) {
    					showMessageDialog(null, "Signature verification failed!");
    					throw new PGPException("Signature verification failed!");
    				}
    				else {
    					String str = new String(signerPublicKey.getRawUserIDs().next(),StandardCharsets.UTF_8);
    					showMessageDialog(null, "Signature verified: " + str);
    					System.out.println("Signature verified: " + str);
    				}
    				
    			}
    		} else {
    			showMessageDialog(null, "message is not a simple encrypted file - type unknown.");
    			throw new PGPException("message is not a simple encrypted file - type unknown.");
    		}
   
    		bOut.close();
    	}
       
       public static boolean checkPassword(PGPSecretKeyRing pgpSecretKeyRing, char[] password) {
    	   try {
			pgpSecretKeyRing.getSecretKey().extractPrivateKey(
			           new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password));
			return true;
		} catch (PGPException e) {

			return false;
		}
       }
       
       
       public static PGPSecretKeyRing findSecretKeyRing(long id) throws IOException, PGPException {
           PGPSecretKeyRingCollection pgpSec = PGPKeyTools.getSecretKeysCollection();
           PGPSecretKey secKey = null;

           Iterator<PGPSecretKeyRing> iter = pgpSec.getKeyRings();
           PGPSecretKeyRing keyRing = null;
           while (iter.hasNext() && secKey == null) {
                   keyRing = iter.next();

                   Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
                   while (keyIter.hasNext()) {
                           PGPSecretKey key = keyIter.next();
                           if ((key.getKeyID() == id)) {
                                   secKey = key;
                                   break;
                           }
                   }
           }

           if (secKey != null) {
                   return keyRing;
           }
           else {
        	   showMessageDialog(null, "CCan't find signing key in key ring.");
                   throw new IllegalArgumentException("Can't find signing key in key ring.");
           }
   }


   public static final PGPPublicKeyRing findPublicKeyRing(long id) throws IOException, PGPException {
           PGPPublicKeyRingCollection pgpPub = PGPKeyTools.getPublicKeysCollection();
           PGPPublicKey pubKey = null;

           Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
           PGPPublicKeyRing keyRing = null;
           while (keyRingIter.hasNext() && pubKey == null) {
                   keyRing = keyRingIter.next();

                   Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
                   while (keyIter.hasNext()) {
                           PGPPublicKey key = keyIter.next();
                           if ((key.getKeyID() == id)) {
                                   pubKey = key;
                                   break;
                           }
                   }
           }

           if (pubKey != null) {
                   return keyRing;
           }
           else {
        	   showMessageDialog(null, "Can't find encryption key in key ring.");
                   throw new IllegalArgumentException("Can't find encryption key in key ring.");
           }
   }
        
}