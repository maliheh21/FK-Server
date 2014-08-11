import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;


public class GroupG {

	public static void createCurveParamter() throws IOException{
		ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(Constants.CURVE_NAME);
		saveCurveParameter(Constants.PARAM_FILE, ecSpec);
	}
	
	private static void saveCurveParameter(String filename, ECNamedCurveParameterSpec ecSpec) throws IOException {
		
		FileOutputStream fos = new FileOutputStream(filename);
		fos.write(ecSpec.getCurve().getA().toBigInteger().toByteArray()); //a
		System.out.println(ecSpec.getCurve().getA().toBigInteger());
		fos.write('\n');
		fos.write(ecSpec.getCurve().getB().toBigInteger().toByteArray()); //b
		fos.write('\n');
		ECCurve curve = ecSpec.getCurve(); 
//		ECFieldF2m field = new ECFieldF2m(((ECCurve.F2m)curve).getQ());
//		fos.write(BigInteger.valueOf(field.getFieldSize()).toByteArray()); //size of field
//		fos.write('\n');
//		fos.write(field.getP().toByteArray()); //p of field
//		fos.write('\n');
		fos.write(ecSpec.getG().getEncoded()); //Generator g
		fos.write('\n');
		fos.write(ecSpec.getN().toByteArray()); //order q
		fos.write('\n');
		System.out.println("P: "+ ecSpec.getN().toString());
		System.out.println("Q: "+ ecSpec.getN().add(BigInteger.valueOf(-1L)).divide(BigInteger.valueOf(2L)));

		
		fos.write(ecSpec.getH().toByteArray()); //Cofactor
		fos.write('\n');
		fos.write(ecSpec.getSeed()); //seed
		fos.close();
	}
	
	public static boolean pointMember(ECCurve curve, ECPoint point) {
	
		ECFieldElement x = point.getAffineXCoord();
		ECFieldElement y = point.getAffineYCoord();

		ECFieldElement a = curve.getA();
		ECFieldElement b = curve.getB();
		ECFieldElement lhs = y.multiply(y);
		ECFieldElement rhs = x.multiply(x).multiply(x).add(a.multiply(x)).add(b);

		boolean pointIsOnCurve = lhs.equals(rhs);
			
		return pointIsOnCurve;
	}
	
//	private ECNamedCurveParameterSpec getCurveParameter(String filename) {
//		return null;
		
//		ECPoint g = ecSpec.getG(); // generator g;
//		BigInteger q = ecSpec.getN(); // prime order q
		
//        this.ecSpec = new ECParameterSpec(
//                       dp.getCurve(),
//                       dp.getG(),
//                       dp.getN(),
//                       dp.getH(),
//                       dp.getSeed());
//	}
	
//	private boolean checkGroupMemberShip(ECNamedCurveParameterSpec ecSpec, String a) {
//		BigInteger alpha = a.toString(16);
//		
//		
//	}
}
