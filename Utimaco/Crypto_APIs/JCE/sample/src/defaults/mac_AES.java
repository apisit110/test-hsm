package defaults;
import CryptoServerJCE.*;
import CryptoServerAPI.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Arrays;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider 
 * for the CryptoServer Hardware Security Module.
 *
 *  Creation of message authentication code (MAC)
 *
 */
public class mac_AES
{
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer JCE : mac_AES ---\n");       
    
    final byte [] aesKeyBytes = { (byte)0xB7, (byte)0xF3, (byte)0x89, (byte)0x3A, (byte)0xAB, (byte)0x15, (byte)0x0B, (byte)0xAF, 
                                  (byte)0xEC, (byte)0xC1, (byte)0x93, (byte)0x10, (byte)0x97, (byte)0x89, (byte)0x3C, (byte)0x38, 
                                  (byte)0x75, (byte)0x1A, (byte)0xD7, (byte)0x28, (byte)0xDD, (byte)0x56, (byte)0xDE, (byte)0xB8,
                                  (byte)0xF1, (byte)0xA4, (byte)0x10, (byte)0x97, (byte)0x75, (byte)0x5B, (byte)0x5E, (byte)0x06 };

    final byte [][] ivs = { { (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, 
                              (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0 },
                            { (byte)1, (byte)1, (byte)1, (byte)1, (byte)1, (byte)1, (byte)1, (byte)1, 
                              (byte)1, (byte)1, (byte)1, (byte)1, (byte)1, (byte)1, (byte)1, (byte)1 } };    
                              
    String modes[] = { "AES",
                       "AESwithPKCS5Padding" };
    
    CryptoServerProvider provider = null;
    
    try
    {
      // load provider    
      provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");    
      System.out.println("Device  : " + provider.getCryptoServer().getDevice());
      
      // authenticate
      provider.loginPassword("JCE", "123456");
                 
      // for all modes
      for (String mode : modes)
      {
        System.out.println("mode: " + mode);
        
        // create key object
        SecretKeySpec aesKeySpec = new SecretKeySpec(aesKeyBytes, "AES");    
        SecretKeyFactory kf = SecretKeyFactory.getInstance("AES",provider);
        SecretKey aesKey = kf.generateSecret(aesKeySpec);                    
        
        // create data
        byte [] data1 = "We are ".getBytes();
        byte [] data2 = "what we were ".getBytes();
        byte [] data3 = "waiting for !".getBytes();      
        
        if (mode.indexOf("Padding") < 0)
        {
          int len = data1.length + data2.length + data3.length;
          
          if ((len = len % 16) != 0)
          {
            byte [] pad = new byte[16 - len];
            Arrays.fill(pad, (byte)0);          
            data3 = cat(data3, pad);
          }
        }
        
        byte [] data = cat(cat(data1, data2), data3);
        //CryptoServerUtil.xtrace("data", data);
        
        for (byte [] iv : ivs)
        {
          IvParameterSpec ivsp = new IvParameterSpec(iv);
          CryptoServerUtil.xtrace("iv", iv);    
          
          // calculate MAC      
          Mac mac = Mac.getInstance(mode, provider);  
          mac.init(aesKey, ivsp);
          byte [] mac1 = mac.doFinal(data);
          
          CryptoServerUtil.xtrace("mac", mac1);
          
          // calculate MAC (demonstrate chunked operation)
          mac.init(aesKey, ivsp);
          mac.update(data1);
          mac.update(data2);    
          mac.update(data3);    
          byte [] mac2 = mac.doFinal();
          
          if (!Arrays.equals(mac1, mac2)) 
            throw new Exception("Mac compare failed");
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
