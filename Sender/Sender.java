import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
//import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class Sender {
  static String IV = "AAAAAAAAAAAAAAAA";
  //static String plaintext = "test text 123\0\0\0"; /*Note null padding*/
  //static String plaintext = "test text 123456ABCDEF987654321"; /*Note null padding*/
  //static String plaintext2 = "2nd piece 789\0\0\0"; /*Note null padding*/
  static String encryptionKey = "0123456789abcdef";
  /*int BLOCK_SIZE = 1024;
  byte[] plaintext[];*/

  public static void main(String [] args) {
    try {
      Scanner scan = new Scanner(System.in);
      System.out.println("Please input the file name: ");
      String fileName = (/* "Sender/" +*/ scan.nextLine());
      
      //System.out.println("==Java==");
      //System.out.println("plain:   " + plaintext);
      String hash = SHA256.md(fileName);
      //System.out.println(SHA256.md(fileName));
      //AES Encryption of SHA 256
      //byte[] cipher = encrypt();
      byte[] hashArray = hash.getBytes("UTF-8");
      System.out.println("Do you want to invert the first byte in SHA256? (Y or N): ");
      String byteInvertInput = scan.nextLine();
      if (byteInvertInput.contains("Y") || byteInvertInput.contains("y")){
        hashArray[0] = (byte) ~hashArray[0];
      }
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
      SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
      cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
      byte[] cipherText = cipher.doFinal(hashArray);
      
      


      BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream("Sender/message.dd"));
      out.write(cipherText);
      out.close();
      System.out.print("cipher:  ");
      for (int i=0; i<cipherText.length; i++)
        //System.out.format("%2X ", new Byte(cipher[i]));
        System.out.format("%2X ", cipherText[i]);
      System.out.println("");

      /*String decrypted = decrypt(cipher);

      System.out.println("decrypt: " + decrypted);*/
      scan.close();
    } catch (Exception e) {
      e.printStackTrace();
    } 

  }

  /*public static byte[] encrypt() throws Exception {
    //Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
    //Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
    Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
    SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
    cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
    return cipher.doFinal(/*plaintext.getBytes("UTF-8"));
  }*/

  /*public static String decrypt(byte[] cipherText) throws Exception{
    //Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
    Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
    //Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
    SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
    return new String(cipher.doFinal(cipherText),"UTF-8");
  }*/
}

