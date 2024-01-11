package defaults;
import CryptoServerJCE.*;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider 
 * for the CryptoServer Hardware Security Module.
 * 
 * RSA benchmark
 *
 */
public class bench_RSA
{
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer JCE - bench_RSA ---\n");
    
    final byte[] data = "+++ data to be signed +++".getBytes();
    int keySizes[] = { 1024, 2048, 4096 };
    int loopCount = 1000;
    String keyName = "RSA Bench";
    
    CryptoServerProvider provider = null;
    
    try
    {
      // load provider    
      provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");    
      System.out.println("Device  : " + provider.getCryptoServer().getDevice());      
    
      // authenticate
      provider.loginPassword("JCE","123456");
      
      // load keystore
      KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
      ks.load(null, null);
      
      for (int i=0; i<keySizes.length; i++)
      {
        int size = keySizes[i];
        
        System.out.println("\nKey size: " + size);

        // Generate RSA key
        //provider.setProperty("Usage", String.valueOf(CryptoServerCXI.CryptoServerCXI.KEY_USAGE_SIGN | CryptoServerCXI.CryptoServerCXI.KEY_USAGE_VERIFY));
        
        KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA",provider);
        kg.initialize(size,null);
        KeyPair keyPair = kg.generateKeyPair();
        PrivateKey prvKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();
        
        if (true)
        {
          // store key
          ks.setKeyEntry(keyName, prvKey, null, provider.getDumyCertificateChain());
          prvKey = (PrivateKey)ks.getKey(keyName, null);
        }
              
        if (false)
        {
          // encrypt data 
          Cipher c = Cipher.getInstance("RSA/None/NoPadding", provider);
          c.init(Cipher.ENCRYPT_MODE, pubKey);
          byte[] crypto = c.doFinal(data);
          byte[] plain = null;
          
          c.init(Cipher.DECRYPT_MODE, prvKey);
          
          Date start = new Date();
          
          for (int ct=0; ct<loopCount; ct++)
          {       
            plain = c.doFinal(crypto);
          }
          
          Date finish = new Date();               
          
          if (Arrays.equals(plain, data) == false)
            throw new Exception("data compare failed");
        
          long duration = finish.getTime() - start.getTime();
          System.out.println("  Duration: " + duration + " ms");     

          long speed = loopCount * 1000 / duration;
          System.out.println("  Speed: " + speed + " op/second");     
        }
        else
        {      
          // sign data
          Signature s = Signature.getInstance("SHA1withRSA",provider);
          s.initSign(prvKey);
          byte [] sig = null;
          
          Date start = new Date();
          
          for (int ct=0; ct<loopCount; ct++)
          {       
            s.update(data);
            sig = s.sign();
          }
          
          Date finish = new Date();
        
          long duration = finish.getTime() - start.getTime();
          System.out.println("  Duration: " + duration + " ms");     

          long speed = loopCount * 1000 / duration;
          System.out.println("  Speed: " + speed + " op/second");     
                
          // Verify Signature
          s.initVerify(pubKey);
          s.update(data);
          if(s.verify(sig) == false)
            throw new Exception("Verification failed");
        }
      }
    }
    catch (Exception ex)
    {
      throw ex;
    }
    finally
    {
      // logoff
      if (provider != null)
        provider.logoff();
    }
    
    System.out.println("Done");
  }
}
