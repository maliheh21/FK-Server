import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class AuxServer {

	public static void main(String[] args) throws IOException,
			InvalidKeyException, NoSuchAlgorithmException,
			InvalidParameterSpecException, InvalidAlgorithmParameterException,
			InvalidKeySpecException {

		byte[] receiveData = new byte[1024];
		InetAddress serverAddr = InetAddress.getByName(Constants.SERVERIP);
		DatagramSocket socket = new DatagramSocket(Constants.SERVERPORT,
				serverAddr);

		// while(true) {
		DatagramPacket receivePacket = new DatagramPacket(receiveData,
				receiveData.length);
		socket.receive(receivePacket);
		String command = new String(receivePacket.getData());
		System.out.println("Command received From Web Server: " + command);
		socket.close();
		// initialization();
		if (command.substring(0, 11).equals("StartSignup"))
			initialization();
		else if (command.substring(0, 11).equals("KeyExchange"))
			keyExchange();
		// String capitalizedSentence = sentence.toUpperCase();
		// sendData = capitalizedSentence.getBytes();
		// DatagramPacket sendPacket = new DatagramPacket(sendData,
		// sendData.length, receivePacket.getAddress(),
		// receivePacket.getPort());
		// socket.send(sendPacket);
		// }
	}

	private static void keyExchange() throws IOException,
			NoSuchAlgorithmException, InvalidKeyException {
		OPRF.getAlpha_sendBeta();

		File file = new File("wi");
		FileInputStream fis = new FileInputStream("wi");
		byte[] wi = new byte[(int) file.length()];
		fis.read(wi);
		fis.close();
		String wiString = new String(wi);
		String[] wiStringSplit = wiString.split(",");
		String wiToSend = wiStringSplit[0] + "," + wiStringSplit[1] + ","
				+ wiStringSplit[2] + "," + wiStringSplit[3] + ","
				+ Constants.MU_PRIME;
		wi = wiToSend.getBytes();

		// we should just send wi but it I was lazy to handle threads so a send
		// and receive
		byte[] receiveData = new byte[1024];
		InetAddress serverAddr = InetAddress.getByName(Constants.SERVERIP);
		DatagramSocket socket = new DatagramSocket(Constants.SERVERPORT3,
				serverAddr);
		DatagramPacket receivePacket = new DatagramPacket(receiveData,
				receiveData.length);
		socket.receive(receivePacket);
		System.out.println("Received request");
		byte[] mu = receivePacket.getData();
		DatagramPacket sendPacket = new DatagramPacket(wi, wi.length,
				receivePacket.getAddress(), receivePacket.getPort());
		socket.send(sendPacket);
		System.out.println("Sent w_i");
		socket.close();
		socket.disconnect();

		String SK_str = "2" + new String(mu).trim() + Constants.MU_PRIME
				+ Constants.CLIENTIP + Constants.SERVERIP;
		System.out.println("SK: " + SK_str);


		Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		SecretKeySpec secret_key = new SecretKeySpec(
				wiStringSplit[5].getBytes(), "HmacSHA256");
		sha256_HMAC.init(secret_key);

		byte[] SK = getHexString(sha256_HMAC.doFinal(SK_str.getBytes()));
		System.out.println("Session Key Computed as: " + new String(SK));

	}

	private static void initialization() throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidParameterSpecException,
			InvalidAlgorithmParameterException, FileNotFoundException,
			IOException, InvalidKeySpecException {
		// SInit();
		// Send pi_i to the client, receive W =(PI, CI), K_i (store K_i in
		// Zeta_i)

		DatagramSocket socket = new DatagramSocket(Constants.SERVERPORT2);
		byte[] receiveData = new byte[4096];
		DatagramPacket receivePacket = new DatagramPacket(receiveData,
				receiveData.length);
		socket.receive(receivePacket);
		String wi = new String(receivePacket.getData());
		String[] temp = wi.split(",");
		socket.close();
		socket.disconnect();

		// Store W_i = (PI, CI) in wi
		// vector PI = public key of servers, vector CI = secret shared with
		// servers, c_i = s_i xor F_pi(r)
		// rwd is secret shared to s_i, r = H(pwd, H'(pwd)^k)
		FileOutputStream fos = new FileOutputStream("wi");
		fos.write((temp[0] + "," + temp[1]).getBytes());
		fos.close();

		// store key in file named zeta
		fos = new FileOutputStream("zeta");
		fos.write(temp[2].getBytes());
		fos.close();

		System.out.println("Vectors received from web client:" + wi);

		socket.close();
	}

	private static byte[] getHexString(byte[] b) {
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result.getBytes();
	}
}
