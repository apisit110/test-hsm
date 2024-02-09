package defaults;
import CryptoServerJCE.*;
import CryptoServerAPI.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider 
 * for the CryptoServer Hardware Security Module.
 *
 * RSA signature creation / verification
 *
 */
public class sign_RSA
{      
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer JCE - sign_RSA ---\n");
    
    int sizes[] = { 1024, 2048 };
    
    Algorithm modes[] = 
    {                   
      new Algorithm("SHA1withRSA",   null),
      new Algorithm("SHA224withRSA", null),
      new Algorithm("SHA256withRSA", null),      
      new Algorithm("SHA384withRSA", null),           
      new Algorithm("SHA512withRSA", null),
      new Algorithm("SHA3-224withRSA", null),
      new Algorithm("SHA3-256withRSA", null),      
      new Algorithm("SHA3-384withRSA", null),           
      new Algorithm("SHA3-512withRSA", null),
      new Algorithm("MD5withRSA",    null),                       
      new Algorithm("SHA1withRSA",   PSSParameterSpec.DEFAULT ),
      new Algorithm("SHA1withRSA",   new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, 32, 1)),
      new Algorithm("SHA256withRSA", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, 32, 1)),
      new Algorithm("SHA256withRSA", new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA256, 0, 1)),
      new Algorithm("SHA256withRSA", new PSSParameterSpec("MD5", "MGF1", MGF1ParameterSpec.SHA1, 10, 1)),      
      new Algorithm("SHA384withRSA", new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA1, 48, 1)),       
      new Algorithm("SHA512withRSA", new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA1, 20, 1)),
      new Algorithm("SHA512withRSA", new PSSParameterSpec("SHA3-256", "MGF1", MGF1ParameterSpec.SHA1, 20, 1))
    };       
    
    CryptoServerProvider provider = null;
    
    try
    {
      // load provider    
      provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");
      System.out.println("Device  : " + provider.getCryptoServer().getDevice());
    
      // authenticate
      provider.loginPassword("JCE", "123456");

      // for all combinations
      for (int ct=0; ct<2; ct++)
      {
        // for all modes
        for (Algorithm mode : modes)
        {
          String algo = mode.algo;
          System.out.println("algo: " + algo);
          
          System.out.println("  Sign on  : " + provider.getName());
          System.out.println("  Verify on: " + provider.getName());               
      
          // for all key sizes
          for (int size : sizes)
          {
            System.out.println("    size: " + size);
            
            // generate RSA key
            KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA", provider);
            kg.initialize(size);
            KeyPair keyPair = kg.generateKeyPair(); 
            PrivateKey privateKey = keyPair.getPrivate();          
            
            // export public key      
            KeyFactory kf = KeyFactory.getInstance("RSA", provider);
            RSAPublicKeySpec publicKeySpec = kf.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
            
            // import public key into other provider
            kf = KeyFactory.getInstance("RSA", provider);
            PublicKey publicKey = (PublicKey)kf.generatePublic(publicKeySpec);
            
            // do test        
            Signature sig = Signature.getInstance(algo, provider);
            Signature ver = Signature.getInstance(algo, provider);
            
            for (int len1=1; len1<33; len1+=3)
            {    
              byte [] data1 = getRandom(len1);
              
              for (int len2=1; len2<22; len2+=2)
              {        
                byte [] data2 = getRandom(len2);            
                
                // sign
                sig.initSign(privateKey);              
                if (mode.param != null)
                  sig.setParameter(mode.param);             
                sig.update(data1);
                sig.update(data2);
                byte [] sign = sig.sign();
              
                // verify
                byte [] data = cat(data1, data2);
                
                ver.initVerify(publicKey);                
                if (mode.param != null)
                  ver.setParameter(mode.param);
                ver.update(data);
                if (ver.verify(sign) == false)
                  throw new Exception("Signature Verification failed");                                     
              }
            }     
          }
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
  
  private static class Algorithm
  {
    String algo;
    AlgorithmParameterSpec param;
    
    public Algorithm(String algo, AlgorithmParameterSpec param)
    {
      this.algo = algo;
      this.param = param;
    }
  }
  
  private static byte [] getRandom(int length)
  {       
    try
    {
      byte[] buf = new byte[length];      
      SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
      
      do
      {
        rng.nextBytes(buf);
      }
      while (buf[0] == 0);
      
      return buf;
    }
    catch (Exception ex)
    {
      return null;
    }    
  }
  
  private static byte [] cat(byte [] a, byte [] b)
  {
    if(a == null) return(b);
    if(b == null) return(a);

    byte [] res = new byte[a.length + b.length];
    System.arraycopy(a,0,res,0,a.length);
    System.arraycopy(b,0,res,a.length,b.length);

    return(res);
  }
}
