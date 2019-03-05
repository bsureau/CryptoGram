package appli;


import javax.crypto.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class Client {

	//private static String RSAPublic;
	private static Key DESKey;
	static byte[] RSAPublicBytes;

	public static void main(String args[]) throws Exception{

		Socket socket_client = null; 
		DataInputStream in; 
		DataOutputStream out; 
		String message = ""; 
		
		System.out.println("Connecting to server...");

		socket_client = new Socket("127.0.0.1", 12345); //connect to server
		System.out.println("Connected!");
		in = new DataInputStream(socket_client.getInputStream());
		out = new DataOutputStream(socket_client.getOutputStream());
		Scanner sc = new Scanner(System.in);

		System.out.println("Waiting for public key...");
		int rsaBytePublicKeySize = in.readInt();
		
		RSAPublicBytes = new byte[rsaBytePublicKeySize];
		in.readFully(RSAPublicBytes, 0, rsaBytePublicKeySize);
		byte[] desKeyByte = chiffrerDESAvecRSA();
		System.out.println("Sending encrypted DES key with RSA public key: ");
		System.out.println(new String(desKeyByte));
		out.writeInt(desKeyByte.length);
		out.flush();
		out.write(desKeyByte, 0, desKeyByte.length);
		out.flush();
		System.out.println("Chat is now on safe mode...");

		while(true) {
			System.out.println("Send a message:");
			message = sc.nextLine();
			System.out.println("Encrypt message with DES...");
			byte[] DESEncryptedByteMessage = encryptMsgWithDES(message);
			System.out.println("Sending encrypted message " + new String(DESEncryptedByteMessage));
			out.writeInt(DESEncryptedByteMessage.length);
			out.flush();
			out.write(DESEncryptedByteMessage, 0, DESEncryptedByteMessage.length);
			out.flush();
			System.out.println("Encrypted message has been sent ! Waiting for a server response...");
			if(message.equals("exit")) {
				break;
			}
			int DESEncryptedMessageSize = in.readInt();
			byte[] DESEncryptedMessage = new byte[DESEncryptedMessageSize];
			in.readFully(DESEncryptedMessage, 0, DESEncryptedMessageSize);
			System.out.println("Received a new encrypted message from server: " + new String(DESEncryptedMessage));
			System.out.println("Decrypt with DES key...");
			String decryptedMsg = decryptMsgWithDES(DESEncryptedMessage);
			System.out.println("Decrypted message is: " + decryptedMsg);
		}
		sc.close();
		socket_client.close();
		System.out.println("Disconnected!");
		System.exit(1);
	}

	private static void genererDES() throws NoSuchAlgorithmException {
		KeyGenerator keygen = KeyGenerator.getInstance("DES");
		keygen.init(56);
		DESKey = keygen.generateKey();
		System.out.println("Creating DES key: " + DESKey.toString());
	}

	private static byte[] chiffrerDESAvecRSA() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidKeySpecException {
		// Récup PublicKey à partir du byte
		X509EncodedKeySpec spec = new X509EncodedKeySpec(RSAPublicBytes);
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PublicKey decodedPublicKey = fact.generatePublic(spec);

		System.out.println("Received public key: " + decodedPublicKey);

		// Encodage DES avec RSA
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, decodedPublicKey);

		genererDES();
		return cipher.doFinal(DESKey.getEncoded());
	}
	
	private static byte[] encryptMsgWithDES(String message) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("DES");
		cipher.init(Cipher.ENCRYPT_MODE, DESKey);
		byte[] byteMessage = message.getBytes();
		return cipher.doFinal(byteMessage);
	}
	
	private static String decryptMsgWithDES(byte[] DESEncryptedMessage) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("DES");
		cipher.init(Cipher.DECRYPT_MODE, DESKey);
		return new String(cipher.doFinal(DESEncryptedMessage));
	}

}
