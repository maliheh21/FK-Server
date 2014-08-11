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

public class AuxServer {
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, InvalidKeySpecException {
		

        byte[] receiveData = new byte[1024];
		InetAddress serverAddr = InetAddress.getByName(Constants.SERVERIP);
		DatagramSocket socket = new DatagramSocket(Constants.SERVERPORT, serverAddr);

//        while(true) {
		  DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
		  socket.receive(receivePacket);
		  String command = new String(receivePacket.getData());
		  System.out.println("Command received From Web Server: " + command);
		  socket.close();
//		  initialization();
		  if (command.substring(0, 11).equals("StartSignup")) initialization();
		  else if (command.substring(0, 11).equals("KeyExchange")) keyExchange();
//		  String capitalizedSentence = sentence.toUpperCase();
//		  sendData = capitalizedSentence.getBytes();
//		  DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, receivePacket.getAddress(), receivePacket.getPort());
//		  socket.send(sendPacket);
//        }
	}

	private static void keyExchange() throws IOException {
		
		File file = new File("wi");
		FileInputStream fis = new FileInputStream("wi");
		byte[] wi = new byte[(int) file.length()];
		fis.read(wi);
		fis.close();
		
		try {
		    Thread.sleep(1000);
		} catch(InterruptedException ex) {
		    Thread.currentThread().interrupt();
		}
		
		DatagramSocket socket = new DatagramSocket();
	    InetAddress clientIPAddress = InetAddress.getByName(Constants.CLIENTIP);	    
	    
	    DatagramPacket sendPacket = new DatagramPacket(wi, wi.length, clientIPAddress, Constants.CLIENTPORT);
		socket.send(sendPacket);
		System.out.println("Sent wi");
		socket.close();
		socket.disconnect();
		OPRF.getAlpha_sendBeta();
		
//	    byte[] receiveData = new byte[4096];
//	    DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
//	    socket.receive(receivePacket);
//	    String received = new String(receivePacket.getData());
//		System.out.println(received);
	}

	private static void initialization() throws InvalidKeyException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, FileNotFoundException, IOException, InvalidKeySpecException {
//		SInit();
//		Send pi_i to the client, receive W =(PI, CI), K_i (store K_i in Zeta_i)
		KeyGen.createSenderKey();
		byte[] pi_i = getHexString(KeyGen.retrivePubKey("pi_i")); 
	    
		DatagramSocket socket = new DatagramSocket();
	    InetAddress clientIPAddress = InetAddress.getByName(Constants.CLIENTIP);	    
	    
	    DatagramPacket sendPacket = new DatagramPacket(pi_i, pi_i.length, clientIPAddress, Constants.CLIENTPORT);
		socket.send(sendPacket);
		
	    byte[] receiveData = new byte[4096];
	    DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
	    socket.receive(receivePacket);
	    String wi = new String(receivePacket.getData());
	    
//	    Store W_i = (PI, CI) in wi 
//	    vector PI = public key of servers, vector CI = secret shared with servers, c_i = s_i xor F_pi(r)
//	    rwd is secret shared to s_i, r = H(pwd, H'(pwd)^k)
	    FileOutputStream fos = new FileOutputStream("wi");
		fos.write(wi.getBytes());
		fos.close();
		
//		store key in file named zeta
	    fos = new FileOutputStream("zeta");
		fos.write(wi.getBytes());
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


