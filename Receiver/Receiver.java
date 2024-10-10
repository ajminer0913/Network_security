import java.security.MessageDigest;
import java.security.PrivateKey;
//import java.util.Arrays;
import java.util.*;
import java.io.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Receiver {
  static String IV = "AAAAAAAAAAAAAAAA";
  //static String plaintext = "test text 123\0\0\0"; /*Note null padding*/
  //static String plaintext = "test text 123456ABCDEF987654321"; /*Note null padding*/
  //static String plaintext2 = "2nd piece 789\0\0\0"; /*Note null padding*/
  //static String encryptionKey = "0123456789abcdef";

  public static void main(String [] args) {
    try {
      Scanner scan = new Scanner(System.in);
      System.out.println("Input the name of the file to be written to: ");
      String fileName = scan.nextLine();
      //RSA Decryption
      Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      
      PrivateKey privKeyY = RSAConfidentiality.readPrivKeyFromFile("YPrivate.key");
      cipherRSA.init(Cipher.DECRYPT_MODE, privKeyY);
      //System.out.println(privKeyY);
      
      

      byte[] cipherTextRSA = new byte[128];
      byte[] plainTextRSA = new byte[117];
      int numBytesReadRSA = cipherTextRSA.length;
      BufferedInputStream bis = new BufferedInputStream(new FileInputStream("message.rsacipher"));
      BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("message.add-msg"));


      while ((numBytesReadRSA = bis.read(cipherTextRSA, 0, cipherTextRSA.length)) == 128){
        
          /*System.out.println("cipherTextRSA: (" + cipherTextRSA.length + "bytes)");
          for (int i=0, j=0; i<cipherTextRSA.length; i++, j++) {
            System.out.format("%2X ", cipherTextRSA[i]) ;
            if (j >= 15) {
              System.out.println("");
              j=-1;
            }
          }*/
          //System.out.println("");
          
          //plainTextRSA = cipherRSA.doFinal(cipherTextRSA, 0, numBytesReadRSA);
          //System.out.println("before decrypt " + numBytesReadRSA);
          //bos.write(plainTextRSA, 0, plainTextRSA.length);
          plainTextRSA = cipherRSA.doFinal(cipherTextRSA, 0, cipherTextRSA.length);

          //System.out.println(plainTextRSA + " whose length is " + plainTextRSA.length);
          
          bos.write(plainTextRSA, 0, plainTextRSA.length);
    
      }
      bis.close();
      bos.close();
      //Old while loop
      /*while (numBytesReadRSA == cipherTextRSA.length){
        //msgFile.read(plaintext, 0, plaintext.length);
        if (numBytesReadRSA <= 0){
          break;
        }
       /*else if(numBytesReadRSA < plaintextRSA.length){
          //lastPlaintextRSA = new byte[numBytesReadRSA];
          plaintextRSA = new byte[numBytesReadRSA];
          //numBytesReadRSA = msgFileRSA.read(lastPlaintextRSA, 0, lastPlaintextRSA.length);
          numBytesReadRSA = msgFileRSA.read(plaintextRSA, 0, plaintextRSA.length);
          ciphertextRSA = cipherRSA.doFinal(plaintextRSA, 0, numBytesReadRSA);
          bosRSA.write(ciphertextRSA, 0, numBytesReadRSA);
        }
        else{
          numBytesReadRSA = bis.read(cipherTextRSA, 0, cipherTextRSA.length);
          
          System.out.println(cipherTextRSA);
          
          //plainTextRSA = cipherRSA.doFinal(cipherTextRSA, 0, numBytesReadRSA);
          System.out.println("before decrypt " + numBytesReadRSA);
          //bos.write(plainTextRSA, 0, plainTextRSA.length);
          plainTextRSA = cipherRSA.doFinal(cipherTextRSA, 0, cipherTextRSA.length);

          System.out.println(plainTextRSA + " whose length is " + plainTextRSA.length);
          
          bos.write(plainTextRSA, 0, plainTextRSA.length);
        }
      }*/
      //Get symmetric key from file
      BufferedReader br = new BufferedReader(new FileReader("symmetric.key"));
      String symmetricKey = br.readLine();
      br.close();

      BufferedInputStream bisAES = new BufferedInputStream(new FileInputStream("message.add-msg"));
      byte[] ciphertextAES = new byte[32];
      byte[] plaintextAES = new byte[32];
      int numBytesReadAES;
      numBytesReadAES = bisAES.read(ciphertextAES, 0, 32);
      //Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
      Cipher cipherAES = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
      //Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
      SecretKeySpec key = new SecretKeySpec(symmetricKey.getBytes("UTF-8"), "AES");
      cipherAES.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
      plaintextAES = cipherAES.doFinal(ciphertextAES,0,32);

      BufferedOutputStream bosAESDecrypt = new BufferedOutputStream(new FileOutputStream("message.dd"));
      bosAESDecrypt.write(plaintextAES, 0, 32);
      
      bosAESDecrypt.close();
      bisAES.close();

      /*System.out.println("plaintextAES: (" + plaintextAES.length + "bytes)");
          for (int i=0, j=0; i<plaintextAES.length; i++, j++) {
            System.out.format("%2X ", plaintextAES[i]) ;
            if (j >= 15) {
              System.out.println("");
              j=-1;
            }
          }*/

      //write original message to input file
      byte[] msgFile = new byte[16*1024];
      int numBytesReadMSG = msgFile.length;
      BufferedInputStream bisMsgFile = new BufferedInputStream(new FileInputStream("message.add-msg"));

      //Skip hash of message
      bisMsgFile.skip(32);
      BufferedOutputStream bosMsgFile = new BufferedOutputStream(new FileOutputStream(fileName));
      
      while (numBytesReadMSG == msgFile.length){
        
        numBytesReadMSG = bisMsgFile.read(msgFile, 0, msgFile.length);
        
        //msgFile.read(plaintext, 0, plaintext.length);
        
        if (numBytesReadMSG <= 0){
          break;
        }
        if (numBytesReadMSG < msgFile.length){
          bosMsgFile.write(msgFile, 0, numBytesReadMSG);
        }
        else{
          bosMsgFile.write(msgFile, 0, msgFile.length);
        }
        

      }
      /*while ((numBytesReadMSG = bisMsgFile.read(msgFile, 0, msgFile.length)) == (16*1024)){
        
        /*System.out.println("cipherTextRSA: (" + cipherTextRSA.length + "bytes)");
        for (int i=0, j=0; i<cipherTextRSA.length; i++, j++) {
          System.out.format("%2X ", cipherTextRSA[i]) ;
          if (j >= 15) {
            System.out.println("");
            j=-1;
          }
        }
            System.out.println("msgFile byte 1: " + msgFile[0]);
            
            //plainTextRSA = cipherRSA.doFinal(cipherTextRSA, 0, numBytesReadRSA);
            
            //bos.write(plainTextRSA, 0, plainTextRSA.length);

            bosMsgFile.write(msgFile, 0, msgFile.length);
      
        }*/
      //System.out.println("numBytesRead: " + numBytesReadMSG);
      
      bosMsgFile.close();
      bisMsgFile.close();
      //bisAES.close();

      System.out.println("locally calculated hash of output file: ");
      byte[] hashArray = SHA256.md(fileName); 

      
      System.out.println("received hash: (" + plaintextAES.length + "bytes)");
      for (int i=0, j=0; i<plaintextAES.length; i++, j++) {
        System.out.format("%2X ", plaintextAES[i]) ;
        if (j >= 15) {
          System.out.println("");
          j=-1;
        }
      }
      boolean hashMatch = true;
      
      for (int i=0; i<hashArray.length; i++) {
            //System.out.format("%2X ", hashArray[i]) ;
        if (hashArray[i] == plaintextAES[i]){
          continue;
        }
        else{
          System.out.println("Hashes did not match");
          hashMatch = false;
          break;
        }
      }

      if (hashMatch == true){
        System.out.println("Hashes Match !");
      }

      //return new String(cipher.doFinal(cipherText),"UTF-8");
      
      /*System.out.println("==Java==");
      System.out.println("plain:   " + plaintext);*/

      /*byte[] cipher = encrypt();

      System.out.print("cipher:  ");
      for (int i=0; i<cipher.length; i++)
        //System.out.format("%2X ", new Byte(cipher[i]));
        System.out.format("%2X ", cipher[i]);
      System.out.println("");

      String decrypted = decrypt(cipher);

      System.out.println("decrypt: " + decrypted);*/

    } catch (Exception e) {
      e.printStackTrace();
    } 
  }

  /*public static byte[] encrypt() throws Exception {
    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
    //Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
    //Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
    SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
    cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
    return cipher.doFinal(plaintext.getBytes("UTF-8"));
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

