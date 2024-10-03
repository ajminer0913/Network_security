import java.io.*;
//import java.security.MessageDigest;
//import java.util.Arrays;
import java.security.*;
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
      
      byte[] hashArray = hash.getBytes();
      System.out.println("Do you want to invert the first byte in SHA256? (Y or N): ");
      String byteInvertInput = scan.nextLine();
      if (byteInvertInput.contains("Y") || byteInvertInput.contains("y")){
        hashArray[0] = (byte) ~hashArray[0];
      }
      hash = new String(hashArray);

      //Display hash in hex
      System.out.println("Hash in Hex: \n");
      for (int k=0, j=0; k<hashArray.length; k++, j++) {
        System.out.format("%2X ", hashArray[k]) ;
        if (j >= 15) {
          System.out.println("");
          j=-1;
        }
      }
      
      //Write hash to message.dd
      BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream("message.dd"));
      out.write(hashArray, 0, hashArray.length);
      out.close();

    
      
      //Read symmetric key from key file

      BufferedReader br = new BufferedReader(new FileReader("symmetric.key"));
      String symmetricKey = br.readLine();
      br.close();
      
      /*try (BufferedInputStream fis = new BufferedInputStream(new FileInputStream("symmetric.key"));
        ObjectInputStream ois = new ObjectInputStream(fis)) {
        secretKey = (SecretKey) ois.readObject();
      }*/

      
      //AES Encryption
      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
      //SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
      SecretKeySpec key = new SecretKeySpec(symmetricKey.getBytes("UTF-8"), "AES");
      cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
      byte[] cipherText = cipher.doFinal(hashArray, 0, 32);
      
      //Write AES Encryption to message.add-msg file
      BufferedOutputStream outAes = new BufferedOutputStream(new FileOutputStream("message.add-msg"));
      outAes.write(cipherText, 0, cipherText.length);
      outAes.close();

      //Open streams for read write to append M to file
      BufferedInputStream msgFile = new BufferedInputStream(new FileInputStream(fileName));
      byte[] plaintext = new byte[16*1024];
      BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("message.add-msg", true));
      //msgFile.read(plaintext);
      int numBytesRead = plaintext.length;
      
      //Read from input file and append it to message.add-msg
      while (numBytesRead == plaintext.length){
        //msgFile.read(plaintext, 0, plaintext.length);
        numBytesRead = msgFile.read(plaintext, 0, plaintext.length);
        if (numBytesRead <= 0){
          break;
        }
        if (numBytesRead < plaintext.length){
          bos.write(plaintext, 0, numBytesRead);
        }
        else{
          bos.write(plaintext, 0, plaintext.length);
        }
        

      }
      msgFile.close();
      bos.close();
      
      //Display cipher text
      System.out.print("\ncipher:  ");
      for (int i=0; i<cipherText.length; i++)
        //System.out.format("%2X ", new Byte(cipher[i]));
        System.out.format("%2X ", cipherText[i]);
      System.out.println("");

      Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      PublicKey pubKeyY = RSAConfidentiality.readPubKeyFromFile("YPublic.key");
      cipherRSA.init(Cipher.ENCRYPT_MODE, pubKeyY);
      

      BufferedInputStream msgFileRSA = new BufferedInputStream(new FileInputStream("message.add-msg"));
      byte[] plaintextRSA = new byte[117];
      byte[] ciphertextRSA = new byte[117];
      //byte[] lastPlaintextRSA = new byte[117];
      //to ensure a new encryption 
      FileOutputStream fosClearRSA = new FileOutputStream("message.rsacipher");
      fosClearRSA.write("".getBytes());
      fosClearRSA.close();
      BufferedOutputStream bosRSA = new BufferedOutputStream(new FileOutputStream("message.rsacipher", true));
      //msgFile.read(plaintext);
      int numBytesReadRSA = plaintextRSA.length;

      while (numBytesReadRSA == plaintextRSA.length){
        //msgFile.read(plaintext, 0, plaintext.length);
        if (numBytesReadRSA <= 0){
          break;
        }
        else if(numBytesReadRSA < plaintextRSA.length){
          //lastPlaintextRSA = new byte[numBytesReadRSA];
          plaintextRSA = new byte[numBytesReadRSA];
          //numBytesReadRSA = msgFileRSA.read(lastPlaintextRSA, 0, lastPlaintextRSA.length);
          numBytesReadRSA = msgFileRSA.read(plaintextRSA, 0, plaintextRSA.length);
          ciphertextRSA = cipherRSA.doFinal(plaintextRSA, 0, numBytesReadRSA);
          bosRSA.write(ciphertextRSA, 0, numBytesReadRSA);
        }
        else{
          numBytesReadRSA = msgFileRSA.read(plaintextRSA, 0, plaintextRSA.length);
          ciphertextRSA = cipherRSA.doFinal(plaintextRSA, 0, plaintextRSA.length);
          bosRSA.write(ciphertextRSA, 0, ciphertextRSA.length);
        }
        
        
        /*if (numBytesReadRSA < plaintextRSA.length){
          ciphertextRSA = cipherRSA.doFinal(plaintextRSA, 0, numBytesReadRSA);
          bosRSA.write(ciphertextRSA, 0, numBytesReadRSA);
        }
        else{
          ciphertextRSA = cipherRSA.doFinal(plaintextRSA, 0, numBytesReadRSA);
          bosRSA.write(plaintextRSA, 0, plaintextRSA.length);
        }*/
        

      }
    msgFileRSA.close();
    bosRSA.close();

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

