package appli;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

public class Server {

	private static KeyPair RSA;
	private static SecretKey DES;
	private static byte[] DESKeyByte; 

	public static void main(String args[]) throws Exception{
		ServerSocket socket_server = null; //server socket
		Socket socket_client = null; //client socket
		DataInputStream in; //input stream 
		DataOutputStream out; //output stream
		String message = "";
		
		socket_server = new ServerSocket(12345); //create a new socket on port n°12345
		Scanner sc = new Scanner(System.in); 
		
		try {
			while(true) {
				socket_client = socket_server.accept(); //listen for a new client 
				System.out.println("Client connected...");
				
				System.out.println("Generating RSA key pair...");
				genererRSA();
				System.out.println("Sending public key: " + RSA.getPublic());
				
				in = new DataInputStream(socket_client.getInputStream()); //get client's input stream
				out = new DataOutputStream(socket_client.getOutputStream()); //get client's ouput stream
				
				byte[] rsaBytePublicKey = RSA.getPublic().getEncoded();
				out.writeInt(rsaBytePublicKey.length);
				out.flush();
				out.write(rsaBytePublicKey, 0, rsaBytePublicKey.length);
				out.flush();
				
				int DESKeyByteSize = in.readInt();
				
				DESKeyByte = new byte[DESKeyByteSize];
				in.readFully(DESKeyByte, 0, DESKeyByteSize);
				System.out.println("Received new encrypted DES key: ");
				System.out.println(new String(DESKeyByte));
				System.out.println("Decrypting DES key with RSA private key...");
				byte[] DESDechiffreByte = dechiffrerDES();
				getDESSecretKey(DESDechiffreByte);
				System.out.println("Decrypted DES key is: " + DES.toString());
				System.out.println("Chat is now on safe mode...");
				while(true) {
					try {			
						int DESEncryptedMessageSize = in.readInt();
						byte[] DESEncryptedMessage = new byte[DESEncryptedMessageSize];
						in.readFully(DESEncryptedMessage, 0, DESEncryptedMessageSize);
						System.out.println("Received a new encrypted message from client : " + new String(DESEncryptedMessage));
						System.out.println("Decrypt with DES key...");
						String decryptedMsg = decryptMsgWithDES(DESEncryptedMessage);
						if(decryptedMsg.equals("exit")){
							break;
						}
						System.out.println("Decrypted message is : " + decryptedMsg); 
						System.out.println("Response:");
						message = sc.nextLine();
						System.out.println("Encrypt message with DES...");
						byte[] DESEncryptedByteMessage = encryptMsgWithDES(message);
						System.out.println("Send encrypted message " + new String(DESEncryptedByteMessage));
						out.writeInt(DESEncryptedByteMessage.length);
						out.flush();
						out.write(DESEncryptedByteMessage, 0, DESEncryptedByteMessage.length);
						out.flush();
						System.out.println("Encrypted message has been sent ! Waiting for a client response...");
					}catch(IOException ex){}
				}
				socket_client.close(); //close client's socket
				System.out.println("Client disconnected.");
			}
		} finally {
			try {
				sc.close();
				socket_server.close();
			}catch(IOException ex) {}
		}
	}

	private static byte[] dechiffrerDES() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, RSA.getPrivate());
		
		return cipher.doFinal(DESKeyByte);
	}

	public static void genererRSA() {
		KeyPairGenerator kpg = null;

		try {
			kpg = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		kpg.initialize(2048);
		RSA = kpg.generateKeyPair();
	}
	
	private static void getDESSecretKey(byte[] DESDechiffreByte) throws InvalidKeySpecException, NoSuchAlgorithmException {
		SecretKeySpec spec = new SecretKeySpec(DESDechiffreByte, "DES");
		DES = SecretKeyFactory.getInstance("DES").generateSecret(spec);
	}
	
	private static byte[] encryptMsgWithDES(String message) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("DES");
		cipher.init(Cipher.ENCRYPT_MODE, DES);
		byte[] byteMessage = message.getBytes();
		return cipher.doFinal(byteMessage);
	}
	
	private static String decryptMsgWithDES(byte[] DESEncryptedMessage) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("DES");
		cipher.init(Cipher.DECRYPT_MODE, DES);
		return new String(cipher.doFinal(DESEncryptedMessage));
	}
}
