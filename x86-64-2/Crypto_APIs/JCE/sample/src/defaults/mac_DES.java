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
public class mac_DES
{
  /**
   * main
   */
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer JCE : mac_DES ---\n");       
    
    final byte [] desKeyBytes = { (byte)0x11, (byte)0x11, (byte)0x11, (byte)0x11, (byte)0x11, (byte)0x11, (byte)0x11, (byte)0x11, 
                                  (byte)0x11, (byte)0x11, (byte)0x11, (byte)0x11, (byte)0x11, (byte)0x11, (byte)0x11, (byte)0x13 };
                              
    final byte [][] ivs = { { (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0 },
                            { (byte)1, (byte)1, (byte)1, (byte)1, (byte)1, (byte)1, (byte)1, (byte)1 } };
                              
    String modes[] = { "DES",
                       "DESwithPKCS5Padding" };
    
    CryptoServerProvider provider = null;
    
    try
    {    
      // load provider    
      provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");
      System.out.println("Device  : " + provider.getCryptoServer().getDevice());
    
      // authenticate
      provider.loginPassword("JCE","123456");
    
      // for all modes
      for (String mode : modes)
      {
        System.out.println("mode: " + mode);
      
        // create key object
        KeyGenerator kg = KeyGenerator.getInstance("DESede", provider);
        kg.init(new CryptoServerKeyGenParameterSpec(168), null);
        SecretKey desKey = kg.generateKey();
          
        // create data
        byte [] data1 = "0123456789".getBytes();
        byte [] data2 = "ABCDEFGHIJ".getBytes();
        
        if (mode.indexOf("Padding") < 0)
        {
          int len = data1.length + data2.length;
          
          if ((len = len % 8) != 0)
          {
            byte [] pad = new byte[8 - len];
            Arrays.fill(pad, (byte)0);          
            data2 = cat(data2, pad);
          }
        }
        
        byte [] data = cat(data1, data2);
        
        for (byte [] iv : ivs)
        {
          IvParameterSpec ivsp = new IvParameterSpec(iv);
          CryptoServerUtil.xtrace("iv", iv);    
          
          // calculate MAC            
          Mac mac = Mac.getInstance(mode, provider);    
          mac.init(desKey, ivsp);               
          byte [] mac1 = mac.doFinal(data);    
          
          CryptoServerUtil.xtrace("mac", mac1);
          
          // calculate MAC (demonstrate chunked operation)
          mac.init(desKey, ivsp);
          mac.update(data1);
          mac.update(data2);            
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
