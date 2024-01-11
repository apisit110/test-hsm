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
 * Elliptic Curve signature creation / verification
 *
 */
public class sign_EC
{  
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer JCE - sign_EC ---\n");
    
    String curves [] = { // brainpool curves
                         "brainpoolP160r1", 
                         "brainpoolP256r1",
                         "brainpoolP320r1",
                         "brainpoolP384r1",
                         "brainpoolP512r1",
                         "brainpoolP160t1",                          
                         "brainpoolP256t1",                         
                         "brainpoolP320t1",                         
                         "brainpoolP384t1",                         
                         "brainpoolP512t1",                         
                         // NIST curves
                         "NIST-P192",
                         "NIST-P224",
                         "NIST-P256",
                         "NIST-P384",
                         "NIST-P521",                                     
                         // binary curves
                         "sect113r1",
                         "sect233r1",
                         "sect283r1",
                         "sect409r1",
                         "sect571r1",
                         "sect163r2",                         
                         "sect163k1",                         
                         "sect233k1",                          
                         "sect283k1",                         
                         "sect409k1",                         
                         "sect571k1",                         
                         // prime curves
                         "secp112r1", 
                         "secp128r1", 
                         "secp160r1",
                         "secp112r2",                         
                         "secp128r2",
                         "secp160r2",                         
                         "secp160k1", // bug                                                  
                         "secp192k1", // bug
                         "secp224k1", // bug
                         "secp256k1"  // bug
                         };
                         
    String modes [] = { "SHA1withECDSA",
    					"SHA224withECDSA",
                        "SHA256withECDSA",
                        "SHA384withECDSA",
                        "SHA512withECDSA",
                        "SHA3-224withECDSA",
                        "SHA3-256withECDSA",
                        "SHA3-384withECDSA",
                        "SHA3-512withECDSA",
                        "MD5withECDSA", 
                        "NONEwithECDSA"
                      };
                        
    CryptoServerProvider provider = null;
    
    try
    {
      // load provider    
      provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");    
      System.out.println("Device  : " + provider.getCryptoServer().getDevice());
    
      // authenticate
      provider.loginPassword("JCE", "123456");
      
      Provider provSign = provider;
      Provider provVerify = provider;
          
      // for all curves
      for (String curve : curves)
      {      
        System.out.println("curve: " + curve);           
             
        // generate EC key
        KeyPairGenerator kg = KeyPairGenerator.getInstance("EC", provSign);      
        CryptoServerECKeyGenParameterSpec ecParam = new CryptoServerECKeyGenParameterSpec(curve);
        kg.initialize(ecParam);      
        KeyPair keyPair = kg.generateKeyPair(); 
        PrivateKey privateKey = keyPair.getPrivate();      
        PublicKey publicKey = keyPair.getPublic();
        
        try
        {
          // export public key                  
          KeyFactory kf = KeyFactory.getInstance("EC", provSign);
          ECPublicKeySpec publicKeySpec = kf.getKeySpec(keyPair.getPublic(), ECPublicKeySpec.class);
          
          // import public key into other provider
          kf = KeyFactory.getInstance("EC", provVerify);
          publicKey = (PublicKey)kf.generatePublic(publicKeySpec);      
        }
        catch (InvalidKeySpecException ex)
        {                       
          ex.printStackTrace();
        }
        
        // for all algorithms
        for (String algo : modes)
        {      
          System.out.println("  algo: " + algo);    
          
          // do test        
          Signature sig = Signature.getInstance(algo, provSign);
          Signature ver = Signature.getInstance(algo, provVerify);
        
          for (int len1=0; len1<33; len1+=3)
          {    
            byte [] data1;            
            if (algo.indexOf("NONE") < 0) data1 = getRandom(len1);              
            else data1 = getRandom(10);
            
            for (int len2=0; len2<22; len2+=2)
            {        
              byte [] data2;            
              if (algo.indexOf("NONE") < 0) data2 = getRandom(len2);              
              else data2 = getRandom(10);            
              
              byte [] data = cat(data1, data2);
              
              // sign
              sig.initSign(privateKey);              
              sig.update(data1);
              sig.update(data2);
              byte [] sign = sig.sign();
            
              // verify
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
      
      if (length > 0)
      {            
        do
        {
          rng.nextBytes(buf);
        }
        while (buf[0] == 0);
      }
      
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
