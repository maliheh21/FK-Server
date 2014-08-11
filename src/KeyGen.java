

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class KeyGen {
	
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, FileNotFoundException, IOException, InvalidKeySpecException {
		createSenderKey();
		createReceiverKey();
	}

	//create Sigma and Pi for Tpake project
	public static void createSenderKey() throws NoSuchAlgorithmException, FileNotFoundException, IOException {
		String pi  = "1234567890";
		String seed = "1234";
		String sigma = Hash.Sha256(seed, pi);
		saveKey(pi.getBytes(), "pi_i");
		saveKey(sigma.getBytes(), "sigma_i");
	}
	
	/* These two are the actual key generation methods, they are simplified for TPAKE project
	 * 
	 * 
	public static void createSenderKey() throws InvalidKeyException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, FileNotFoundException, IOException {
		DHParameterSpec dhSkipParamSpec = generateKeyParameter();
		KeyPair senderKpair = generateKey(dhSkipParamSpec);	
		
		SaveKeyPair("s", senderKpair);
//	    byte[] pubKeyEnc = senderKpair.getPublic().getEncoded();
//	    byte[] privKeyEnc = senderKpair.getPrivate().getEncoded();
//	    saveKey(pubKeyEnc, "spubkey");
//	    saveKey(privKeyEnc, "sprivkey");	
	 
	}
	
	*/

	public static void createReceiverKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidParameterSpecException {
		// TODO Auto-generated method stub
		byte[] senderPubKeyEnc = retrivePubKey("spubkey");
		
		DHParameterSpec dhParamSpec = retrieveKeyParameter(senderPubKeyEnc);
        KeyPair receiverKpair= generateKey(dhParamSpec);

        SaveKeyPair("r", receiverKpair);

//	    byte[] pubKeyEnc = receiverKpair.getPublic().getEncoded();
//	    byte[] privKeyEnc = receiverKpair.getPrivate().getEncoded();
//	    saveKey(pubKeyEnc, "rpubkey");
//	    saveKey(privKeyEnc, "rprivkey");
		
	}
	

	private static KeyPair generateKey(DHParameterSpec dhSkipParamSpec) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, InvalidKeyException {
	    
	    
	    /*
	     * Alice creates her own DH key pair, using the DH parameters from
	     */
	    System.out.println("Generate DH keypair ...");
	    KeyPairGenerator senderKpairGen = KeyPairGenerator.getInstance("DH");
	    senderKpairGen.initialize(dhSkipParamSpec);
	    KeyPair senderKpair = senderKpairGen.generateKeyPair();
	    
	    return senderKpair;
	}
	
	
	
	 /*
	 * Generate Parameters
	 */
	
	private static DHParameterSpec generateKeyParameter()
			throws NoSuchAlgorithmException, InvalidParameterSpecException {
		System.out.println
	    ("Creating Diffie-Hellman parameters ...");
	    
		DHParameterSpec dhSkipParamSpec;
	    AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
	    paramGen.init(512);
	    AlgorithmParameters params = paramGen.generateParameters();
	    dhSkipParamSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);
		return dhSkipParamSpec;
	}
	
	 /*
	 * Retrieve Parameters from a public key
	 */	
	public static DHParameterSpec retrieveKeyParameter (byte[] pubKeyEnc) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException {

        KeyFactory receiverKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec
            (pubKeyEnc);
        PublicKey senderPubKey = receiverKeyFac.generatePublic(x509KeySpec);

        DHParameterSpec dhParamSpec = ((DHPublicKey)senderPubKey).getParams();
        return dhParamSpec;

	}

	
	
	
	
	 /*
	 * Retrieve a pub key from a file 
	 */
	public static byte[] retrivePubKey(String pubFileName) throws NoSuchAlgorithmException,
	InvalidKeySpecException, IOException {
				

		File filePublicKey = new File(pubFileName);
		FileInputStream fis = new FileInputStream(pubFileName);
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();
		
		KeyFactory receiverKeyFac = KeyFactory.getInstance("DH");
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(encodedPublicKey);
		PublicKey pubKey = receiverKeyFac.generatePublic(x509KeySpec);
		
		return pubKey.getEncoded();	
	}
	
	 /*
	 * Retrieve private key from a file 
	 */
	public static byte[] retrivePrivKey(String privFileName) throws NoSuchAlgorithmException,
	InvalidKeySpecException, IOException {
		
		File filePrivateKey = new File(privFileName);
		FileInputStream fis = new FileInputStream(privFileName);
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();
		
		KeyFactory receiverKeyFac = KeyFactory.getInstance("DH");	 
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		PrivateKey privateKey = receiverKeyFac.generatePrivate(privateKeySpec);
		
		return encodedPrivateKey;
	}

	
	public static void SaveKeyPair(String filename, KeyPair keyPair) throws IOException {
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		 
		// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
		publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(filename+"pubkey");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
		 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
		privateKey.getEncoded());
		fos = new FileOutputStream(filename+"privkey");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}
	
	 /*
	 * Save key to a file 
	 */
	private static void saveKey(byte[] keyEnc, String fileName)
			throws FileNotFoundException, IOException {
	    FileOutputStream fos = new FileOutputStream(fileName);
	    fos.write(keyEnc);
	    fos.close();
	}
	
	 /*
	 * Retrieve file content to receive PI, wi and zeta for TPAKE project
	 */
	public static String retrivePi(String fileName) throws IOException {
		File filePublicKey = new File(fileName);
		FileInputStream fis = new FileInputStream(fileName);
		byte[] content = new byte[(int) filePublicKey.length()];
		fis.read(content);
		fis.close();		
		return new String(content);	
	}
	
	
}