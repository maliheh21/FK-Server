import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.EllipticCurve;
import java.util.Random;

import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;


public class Tests {

	/**
	 * @param args
	 * @throws NoSuchAlgorithmException 
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException {
		
		String curveName = Constants.CURVE_NAME;
		ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
		ECCurve curve = ecSpec.getCurve();
		
//		EC5Util ecUtil = new EC5Util();
//		EllipticCurve jCurve = EC5Util.convertCurve(curve, null);
//		ECPoint ecNewPoint  = EC5Util.convertPoint(curve, Constants.HASH_OF_PASSWORD, false);
		
//		String rwdEncoded = FOPRF.OPRF_Encode(new BigInteger(Constants.OPRF_KEY, 16), ecNewPoint); //rwd = F_k(pwd) = H'(pwd)^k
//		ECPoint rwdAsPoint = curve.decodePoint(Hex.decode(rwd));
//		System.out.println("RWD " + rwdEncoded + "\n");
//		int index = rwdEncoded.indexOf(',');
//		String rwd = rwdEncoded.substring(0, index) + rwdEncoded.substring(index+1);
//		System.out.println("RWD_Secret " + rwd + "\n");

//		System.out.println(Hash(Constants.PASSWORD, rwd)); //r = H(pwd, H'(pwd)^k)
		
		BigInteger q = ecSpec.getN().add(BigInteger.valueOf(-1L)).divide(BigInteger.valueOf(2L));
		BigInteger p = ecSpec.getN();
		BigInteger ro = randomRo(q); 
		BigInteger roInverse = ro.modInverse(q);
		System.out.println("ro mult roInv: " + ro.multiply(roInverse).mod(q));
		
		System.out.println("q " + q.toString(16) + "\nro " + ro.toString(16) + "\nroInverse " + roInverse.toString(16));
		
//		ECPoint eck1  = EC5Util.convertPoint(curve, Constants.HASH_OF_S1, false);
//		String k_1 = FOPRF.OPRF_Encode(new BigInteger(rwd, 16), eck1); //k_1 = F_rwd(i) = H'(i)^rwd
//		ECPoint k1AsPoint = curve.decodePoint(k_1);
//		System.out.println("k_1 " + k_1 + "\n");
		
//		ECPoint eck2  = EC5Util.convertPoint(curve, Constants.HASH_OF_S2, false);
//		String k_2 = FOPRF.OPRF_Encode(new BigInteger(rwd, 16), eck2); //k_1 = F_rwd(i) = H'(i)^rwd
//		ECPoint k3AsPoint = curve.decodePoint(k_2);
//		System.out.println("k_2 " + k_2 + "\n");
		
//		System.out.println("rwd_x " + new BigInteger("5701a4ffee748ba482b77a70967ebb23e5fe1529f80ae24b41a53dfdd55e8e8dee07f5f", 16));
//		System.out.println("h_p " + new BigInteger("0000000005157E4295D6FF0C5B3D9D00FA1B0D76A04ADBF90252C748B2C46850BDCF32AFBF9C5AAB", 16));
//		
//		BigInteger someRo = new BigInteger("435395209234187956232110864129176817853827586188213605516272948531014987742579182669",10);
//		System.out.println(someRo.toString(16));
//		System.out.println("ro " + new BigInteger("176016c537c83316470ff3a47140ae383fd32d3d4a37654961e4e5c5b42706b90863f75", 16));
//
		
		
				
	}
	
	public static String Hash(String seed, String message) throws NoSuchAlgorithmException {
		
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		String x = message + seed;
		messageDigest.update(x.getBytes());
		return byteArray2Hex(messageDigest.digest());		
	}
	
	public static BigInteger randomRo(BigInteger q){
		
		System.out.println(q.bitLength());
		
		// 	modInverse(BigInteger m)
		//		Returns a BigInteger whose value is (this-1 mod m).
		Random rand = new Random();
		BigInteger result = new BigInteger(q.bitLength(), rand);
	    while( result.compareTo(q) >= 0 ) {
	        result = new BigInteger(q.bitLength(), rand);
	    }
	    return result;
		
	}
	
	private static final char[] hex = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	public static String byteArray2Hex(byte[] bytes) {
	    StringBuffer sb = new StringBuffer(bytes.length * 2);
	    for(final byte b : bytes) {
	        sb.append(hex[(b & 0xF0) >> 4]);
	        sb.append(hex[b & 0x0F]);
	    }
	    return sb.toString();
	}

	
	
}
