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
 * DSA signature creation / verification
 *
 */
public class sign_DSA
{    
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer JCE - sign_DSA ---\n");
    
    String PROV_SIGN;
    String modes [];
  
    if (System.getProperty("os.name").indexOf("AIX") >= 0)
    {
      PROV_SIGN = "IBMJCE";
      
      modes = new String [] { "SHA1withDSA" };
    }
    else
    {
      PROV_SIGN = "SUN";
      
      modes = new String [] { "SHA1withDSA", 
                              "NONEwithDSA"
                            };
    }
    
    int sizes[] = { 1024, 2048 }; 

    CryptoServerProvider provider = null;
    
    try
    {           
      // load provider    
      provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg"); 
      System.out.println("Device  : " + provider.getCryptoServer().getDevice());      
    
      // authenticate
      provider.loginPassword("JCE", "123456");
      
      Provider provSign;
      Provider provVerify;
      
      // for all combinations
      for (int ct=0; ct<2; ct++)
      {
        // for all algorithms
        for (String algo : modes)
        {
          System.out.println("algo: " + algo);
          
          if (ct == 0)
          {
            provSign = provider;
            provVerify = Security.getProvider(PROV_SIGN);
          }
          else
          {         
            provSign = Security.getProvider(PROV_SIGN);
            provVerify = provider;
          }
          
          System.out.println("  Sign on  : " + provSign.getName());
          System.out.println("  Verify on: " + provVerify.getName());               
      
          // for all key sizes
          for (int size : sizes)
          {
            // Other providers do not support SHA1 signing with larger key sizes
            if (size > 1024 && provSign != provider)
              continue;
            
            System.out.println("    size: " + size);
            
            // generate DSA key
            KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA", provSign);
            kg.initialize(size);
            KeyPair keyPair = kg.generateKeyPair(); 
            PrivateKey privateKey = keyPair.getPrivate();          
            
            // export public key      
            KeyFactory kf = KeyFactory.getInstance("DSA", provSign);
            DSAPublicKeySpec publicKeySpec = kf.getKeySpec(keyPair.getPublic(), DSAPublicKeySpec.class);
            
            // import public key into other provider
            kf = KeyFactory.getInstance("DSA", provVerify);
            PublicKey publicKey = (PublicKey)kf.generatePublic(publicKeySpec);
            
            // do test        
            Signature sig = Signature.getInstance(algo, provSign);
            Signature ver = Signature.getInstance(algo, provVerify);
            
            for (int len1=1; len1<33; len1+=3)
            {    
              byte [] data1;            
              if (algo.indexOf("NONE") < 0) data1 = getRandom(len1);              
              else data1 = getRandom(10);
              
              for (int len2=1; len2<22; len2+=2)
              {        
                byte [] data2;            
                if (algo.indexOf("NONE") < 0) data2 = getRandom(len2);              
                else data2 = getRandom(10);
                
                // sign
                sig.initSign(privateKey);              
                sig.update(data1);
                sig.update(data2);
                byte [] sign = sig.sign();
              
                // verify
                byte [] data = cat(data1, data2);
                
                ver.initVerify(publicKey);                
                ver.update(data);
                if (ver.verify(sign) == false)
                {
                  CryptoServerUtil.xtrace("data", data);
                  CryptoServerUtil.xtrace("sign", sign);
                  throw new Exception("Signature Verification failed");                                     
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
    
    System.out.println("Done");
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
