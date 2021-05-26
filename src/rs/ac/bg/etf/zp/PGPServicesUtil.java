package rs.ac.bg.etf.zp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
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
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import om160246d.PGPKeyTools;







public class PGPServicesUtil {
	
	public static byte[] encodeRadix64(byte[] data ) throws IOException {
		ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        org.bouncycastle.bcpg.ArmoredOutputStream armoredOutputStream = new org.bouncycastle.bcpg.ArmoredOutputStream(byteOutputStream);
        armoredOutputStream.write(data);
        armoredOutputStream.close();
        byte[] encodedData = byteOutputStream.toByteArray();
        byteOutputStream.close();
        return encodedData;
		
	}
	
	public static InputStream decodeRadix64(InputStream data) throws IOException {
		 return PGPUtil.getDecoderStream(data);
		
	}
	
	 public static byte[] compress(byte[] data, int algorithm) throws IOException
	    {
	        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
	        PGPCompressedDataGenerator compressionGenerator = new PGPCompressedDataGenerator(algorithm);
	        OutputStream compressedStream = compressionGenerator.open(byteOutputStream); // open it with the final destination
	        compressedStream.write(data);
	        compressedStream.close();
	        byte[] compressedData = byteOutputStream.toByteArray();
	        byteOutputStream.close();
	        return compressedData;
	    }
	 
	 public static InputStream decompress(InputStream data) throws Exception {

		 JcaPGPObjectFactory pgpFactory = new JcaPGPObjectFactory(data);
		    Object object  =pgpFactory.nextObject();
		    if(!(object instanceof PGPCompressedData)) throw new Exception("Unable to decompress message");
		    return ((PGPCompressedData) object).getDataStream();
	 }
	 
	 
	 public static byte[] encrypt(byte[] data, PGPPublicKey key , int algorithm) throws IOException, PGPException {
		 
		 
		 OutputStream outputStream = new ByteArrayOutputStream();

	        

	        PGPEncryptedDataGenerator encryptionGenerator = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(algorithm).setSecureRandom(new SecureRandom()).setProvider("BC"));
	        encryptionGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(key).setProvider("BC"));
	        		// STA RADI OVO
	        OutputStream encryptedOutputStream = encryptionGenerator.open(outputStream, data.length);

	        encryptedOutputStream.write(data);
	        encryptedOutputStream.close();

	      

	        return ((ByteArrayOutputStream)outputStream).toByteArray();
	 }
	 
	 public static InputStream decrypt(InputStream data, char[] password) throws Exception {
		 
	
			JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(data);
			Object object= objectFactory.nextObject();
			
			
			if (object instanceof PGPEncryptedDataList) 
			{
			    PGPEncryptedDataList enc = (PGPEncryptedDataList) object;
				java.util.Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
			    PGPPrivateKey sKey = null;
			    PGPPublicKeyEncryptedData pbe = null;
			    while (sKey == null && it.hasNext())
			    {
			        pbe = (PGPPublicKeyEncryptedData) it.next();
		            PGPSecretKeyRing privateKeyRing = getPrivateKeyRing(pbe.getKeyID());
		            //TODO DOHVATANJE RINGA KLJUCEVA
		            
		            if (privateKeyRing != null)
		            {
		            	java.util.Iterator<PGPSecretKey> iterPriv = privateKeyRing.getSecretKeys();
		            	PGPSecretKey masterKey = iterPriv.next();
		            	PGPSecretKey secretKey = iterPriv.next();
		            	
		        		PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
								.setProvider("BC").build(password));
				
		            	
		            	  PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey);
		                  InputStream decryptedStream = pbe.getDataStream(dataDecryptorFactory);
		            	return decryptedStream;
		            }
		            else
		            {
		            	throw new Exception("Private key not found");
		            }
			    }
			} else throw new Exception("Decryption phase error");
			return null;
			
		 
	 }
	 
	 public static boolean verifySignature(InputStream data) throws Exception {
		 data = new ByteArrayInputStream(data.readAllBytes());
		 JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(data);
			Object object= objectFactory.nextObject();
			
		
		if (object instanceof PGPOnePassSignatureList) 
		{
			PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) object;
            PGPOnePassSignature onePassSignature = onePassSignatureList.get(0);
            
            
            
            
            long keyId = onePassSignature.getKeyID();

            
            PGPPublicKey publicKey = getPublicKeyByID(keyId);
            if (publicKey == null)
            {
            	throw new Exception("Key for signature verification not found");
            }

            
            
            
            
            
            
            onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);

            InputStream toVerify = ((PGPLiteralData) objectFactory.nextObject()).getInputStream();
            
            onePassSignature.update(toVerify.readAllBytes());

            PGPSignatureList signatureList = (PGPSignatureList) objectFactory.nextObject();
            PGPSignature signature = signatureList.get(0);

            if (onePassSignature.verify(signature)) {
            	System.out.println("Ovde");
            		return true;
            }
            else
            {
            	System.out.println("Ovde1");
            	throw new Exception("Verification failed, signature integrity corrupted");
            	
            }
		}
		System.out.println("Ovde2");
		throw new Exception("Verification error");
	 }


	 public static byte[] sign(byte[] data , PGPPrivateKey privateKey, int algorithm) throws PGPException, IOException {
		 
		 PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(algorithm, PGPUtil.SHA1).setProvider("BC"));
     	
     	ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
         BCPGOutputStream helperStream = new BCPGOutputStream(byteStream);
         
         signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
         signatureGenerator.generateOnePassVersion(false).encode(helperStream);
         
         PGPLiteralDataGenerator     lGen = new PGPLiteralDataGenerator();
         OutputStream                os = lGen.open(helperStream, PGPLiteralData.BINARY,"tmp", data.length, new Date());
         InputStream is = new ByteArrayInputStream( data );

         int ch;

         while ( ( ch = is.read() ) >= 0 )
         {
        	 signatureGenerator.update( ( byte ) ch );
             os.write( ch );
         }

      
         
         lGen.close();

         signatureGenerator.generate().encode(helperStream);

         byte[] signed= byteStream.toByteArray();
         
      
         byteStream.close();
         helperStream.close();
         return signed;
		 
	 }
	 
	 public static void reportError(String message) {
		 System.err.println(message);
	 }
	 

	 
	 private static PGPPublicKey getPublicKeyByID(long keyId) {
		try {
			return PGPKeyTools.getPublicKeysCollection().getPublicKey(keyId);
		} catch (PGPException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	 }
	 
	 private static PGPSecretKeyRing getPrivateKeyRing(long id) {
		 PGPSecretKey pgpSec;
		try {
			return  PGPKeyTools.getSecretKeysCollection().getSecretKeyRing(id);
			 
		} catch (PGPException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

			return null;
		 }
	 
	 public static void main(String [] args) {
		 try {
			byte[] data = IOUtil.readFromFile("srpski.txt");
			data= compress(data, CompressionAlgorithmTags.ZIP);
			data = encodeRadix64(data);
			IOUtil.writeToFile("srpski-compressed.txt", data);
			
			 data = IOUtil.readFromFile("srpski-compressed.txt");
			 data = decodeRadix64(new ByteArrayInputStream(data)).readAllBytes();
			 data = decompress(new ByteArrayInputStream(data)).readAllBytes();
			 IOUtil.writeToFile("srpski-decompressed.txt", data);
				
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			ErrorReportUtil.reportError(e);
		}
		 
	 }

}
