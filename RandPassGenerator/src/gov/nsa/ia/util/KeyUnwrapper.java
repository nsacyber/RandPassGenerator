package gov.nsa.ia.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * KeyUnwrapper is a class that decrypts an encrypted generated hexadecimal key using 256 bit AES key derived from random password.
 * Saves unencrypted key as .txt file.
 * 
 * @author amsagos
 */

public class KeyUnwrapper {
	
	//256-bit salt generated from DRNG
	private static String saltinput = "762043c38a8e1ad1c8502ec6e53d8c503fe9b28bf73f583e4fadd5888737a5ae";
	

	 public static void fileProcessor(String PW,File encryptedFile,File decryptedFile){
		 try {
			 
			//DPKDF2  NIST SP 800-132
			// salt value
			 byte[] salt = new String(saltinput).getBytes();
			  
			 // iteration count
			 int iterCount = 100000;
			  
			 int derivedKeyLength = 256 ; // Should be at least 256 bits.
			  
			 KeySpec spec = new PBEKeySpec(PW.toCharArray(), salt, iterCount, derivedKeyLength);
			 SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			 
			 SecretKey secretKey = f.generateSecret(spec);
			 
			 SecretKey cipherKey = new SecretKeySpec(secretKey.getEncoded(), "AES");
			 
			//RFC 3394
			 int cipherMode = Cipher.UNWRAP_MODE;
			 Cipher cipher = Cipher.getInstance("AESWrap", "SunJCE");
			   
			// unwrap key

		       if (PW.getBytes().length < 16) {
		    	   System.out.println("Password must be at least 16 characters, failed to decrypt key");
		    	   return;
		       }else {
		    	   cipher.init(cipherMode, cipherKey, cipher.getParameters()); 
		       }
		       FileInputStream inputStream = new FileInputStream(encryptedFile);
			      byte[] inputBytes = new byte[(int) encryptedFile.length()];
			      inputStream.read(inputBytes);
			      Key outputKey = cipher.unwrap(inputBytes, "AES", Cipher.SECRET_KEY);
			      
			      byte[] outputBytes = outputKey.getEncoded();
			       
			      FileOutputStream outputStream = new FileOutputStream(decryptedFile);
			      outputStream.write(outputBytes);

			      inputStream.close();
			      outputStream.close();

		    } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IOException | NoSuchProviderException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
		    	e.printStackTrace();
			}
	 }
	
	 //test
	 private static String DATA ="6b6c315f62b0453608169c73893d8f0abe79fdf63a078d5c2bc9bdcb57fa028c";
	 private static String DATA2 ="6b6c315f62b0453608169c73893d8f0abe79fdf63a078d5c2bc9bdcb57fa0";
	 private static String KEKPW ="9fXMi5JvoHDIGQBM9fXMi5JvoHDIGQBM";
	 private static File EFile = new File("test.enc");
	 private static File DEFile = new File("test_Decrypted.txt");
	 
	 public static void main(String[] args) {
		 
			try {
				KeyUnwrapper.fileProcessor(KEKPW,EFile,DEFile);
				FileReader inputStream = new FileReader(DEFile);			
				BufferedReader breader = new BufferedReader(inputStream);
				String Unwrapped = breader.readLine();
				if (Unwrapped.equals(DATA) && !Unwrapped.equals(DATA2)) {
			     System.out.println("Test Successful");
				}else {
					System.out.println("Test Failed");
				}
				breader.close();
			 } catch (Exception ex) {
			     System.out.println(ex.getMessage());
		             ex.printStackTrace();
			 }
	 }

}
