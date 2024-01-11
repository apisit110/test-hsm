package defaults;
import CryptoServerJCE.*;
import CryptoServerAPI.*;
import java.io.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider 
 * for the CryptoServer Hardware Security Module.
 *
 * RSA encryption / decryption
 *
 */
public class crypt_RSA
{
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer JCE - crypt_RSA ---\n");
    
    String PROV_CIPHER;
    String PROV_KEYFACTORY;    
    int sizes[];
    
    if (System.getProperty("os.name").indexOf("AIX") >= 0)
    {
      PROV_CIPHER = "IBMJCE";
      PROV_KEYFACTORY  = "IBMJCE";
      
      sizes = new int [] { 1024, 1536, 2048 };
    }
    else 
    {
      PROV_CIPHER = "SunJCE";
      PROV_KEYFACTORY  = "SunRsaSign";      
      
      sizes = new int [] { 1024, 1111, 1234, 2048 };
    }
                
    Algorithm modes[] = 
    {
      new Algorithm("RSA/ECB/NoPadding", null),     
      new Algorithm("RSA/ECB/PKCS1Padding", null),
      new Algorithm("RSA/ECB/OAEPPadding", new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, new PSource.PSpecified("Utimaco".getBytes()))),      
      new Algorithm("RSA/ECB/OAEPPadding", new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, new PSource.PSpecified("Sophos".getBytes()))),
      new Algorithm("RSA/ECB/OAEPPadding", new OAEPParameterSpec("SHA3-256", "MGF1", MGF1ParameterSpec.SHA1, new PSource.PSpecified("Sophos".getBytes()))),
    };
    
    CryptoServerProvider provider = null;
    
    try
    {       
      // load provider    
      provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");
      System.out.println("Device  : " + provider.getCryptoServer().getDevice());
      
      // authenticate
      provider.loginPassword("JCE", "123456");
      
      Provider provGenerate;
      Provider provImport;
      Provider provEncrypt;
      Provider provDecrypt;
      
      // for all combinations
      for (int ct=0; ct<2; ct++)
      {
        // for all modes
        for (Algorithm mode : modes)
        {
          String algo = mode.algo;
          System.out.println("algo: " + algo);
          
          if (mode.param != null)
          {
            provGenerate = provider;
            provImport = provider;
            provEncrypt = provider;
            provDecrypt = provider;  
          }
          else if (ct == 0)
          {
            provGenerate = provider;
            provImport = Security.getProvider(PROV_KEYFACTORY);    
            provEncrypt = Security.getProvider(PROV_CIPHER);
            provDecrypt = provider;    
          }
          else
          {         
            provGenerate = Security.getProvider(PROV_KEYFACTORY);    
            provImport = provider;      
            provEncrypt = provider;
            provDecrypt = Security.getProvider(PROV_CIPHER);  
          }
          
          System.out.println("  Encrypt on: " + provEncrypt.getName());
          System.out.println("  Decrypt on: " + provDecrypt.getName());
      
          // for all key sizes
          for (int size : sizes)
          {
            System.out.println("    size: " + size);
            
            // generate RSA key
            KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA", provGenerate);
            kg.initialize(size, null);
            KeyPair keyPair = kg.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            
            // export public key      
            KeyFactory kf = KeyFactory.getInstance("RSA", provGenerate);
            RSAPublicKeySpec publicKeySpec = kf.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
          
            // import public key into other provider
            kf = KeyFactory.getInstance("RSA", provImport);
            PublicKey publicKey = (PublicKey)kf.generatePublic(publicKeySpec);
                        
            // do test    
            Cipher enc = Cipher.getInstance(mode.algo, provEncrypt);
            enc.init(Cipher.ENCRYPT_MODE, publicKey, mode.param);            
            
            Cipher dec = Cipher.getInstance(mode.algo, provDecrypt);
            dec.init(Cipher.DECRYPT_MODE, privateKey, mode.param);
            
            for (int len1=1; len1<32; len1++)
            {
              byte [] data1 = getRandom(len1);
              
              for (int len2=1; len2<11; len2++)
              {
                byte [] data2 = getRandom(len2);
                
                // encrypt
                enc.update(data1);
                byte [] crypto = enc.doFinal(data2);          
            
                // decrypt
                byte [] plain = strip(dec.doFinal(crypto));              
                
                // compare
                byte [] data = cat(data1, data2);
                
                if (Arrays.equals(data,plain) == false)
                {
                  CryptoServerUtil.xtrace("data1", data1);
                  CryptoServerUtil.xtrace("data2", data2);
                  CryptoServerUtil.xtrace("plain", plain);
                  CryptoServerUtil.xtrace("crypto", crypto);                
                  throw new Exception("Compare failed");               
                }
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
    
    // logoff
    provider.logoff();
    
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
  
  private static byte [] strip(byte [] a)
  {
    int ofs;
    
    for (ofs=0; ofs<a.length; ofs++)
      if (a[ofs] != 0)
        break;
    
    byte [] res = new byte[a.length - ofs];
    System.arraycopy(a,ofs,res,0,res.length);
    return(res);
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
