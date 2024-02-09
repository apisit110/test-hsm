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
 * Test DES encryption / decryption with all keysizes and modes
 */
public class crypt_DES
{
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer JCE - crypt_DES ---\n");
    
    String PROV_CIPHER;
    
    if (System.getProperty("os.name").indexOf("AIX") >= 0)
      PROV_CIPHER  = "IBMJCE";
    else 
      PROV_CIPHER  = "SunJCE";
    
    int sizes[] = { 56, 112, 168 };
    
    String modes[] = { "/ECB/NOPADDING",
                       "/ECB/PKCS5PADDING",
                       "/ECB/ISO10126PADDING",
                       "/CBC/NOPADDING",
                       "/CBC/PKCS5PADDING",
                       "/CBC/ISO10126PADDING"
                     };

    CryptoServerProvider provider = null;
    
    try
    {    
      // load provider    
      provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");  
      System.out.println("Device  : " + provider.getCryptoServer().getDevice());      
      
      // authenticate
      provider.loginPassword("JCE", "123456");
      
      // for all key sizes
      for (int keysize : sizes)
      {
        System.out.println("keysize: " + keysize);
        String algorithm = (keysize == 56) ? "DES" : "DESede";
        
        // Generate DES key                 
        CryptoServerKeyGenParameterSpec desParam = new CryptoServerKeyGenParameterSpec(keysize);        
        desParam.setPlainExportable(true);
        
        KeyGenerator kg = KeyGenerator.getInstance(algorithm, provider);
        kg.init(desParam, null);
        SecretKey desKey = kg.generateKey();

        // convert key for Sun Provider
        SecretKeyFactory kf = SecretKeyFactory.getInstance(algorithm, provider);
        SecretKey desKey2;
        
        if (keysize == 56)
        {
          DESKeySpec desKeySpec = (DESKeySpec)kf.getKeySpec(desKey, DESKeySpec.class);                
          kf = SecretKeyFactory.getInstance(algorithm, "SunJCE");
          desKey2 = kf.generateSecret(desKeySpec);
        }
        else
        {
          DESedeKeySpec des3KeySpec = (DESedeKeySpec)kf.getKeySpec(desKey, DESedeKeySpec.class);        
          kf = SecretKeyFactory.getInstance(algorithm, "SunJCE");
          desKey2 = kf.generateSecret(des3KeySpec);
        }
        
        // for all modes
        for (String mode : modes)
        {
          mode = algorithm + mode;        
          System.out.println("  mode: " + mode);

          Cipher c = Cipher.getInstance(mode, provider);
          Cipher c2 = Cipher.getInstance(mode, PROV_CIPHER);

          IvParameterSpec ivsp = null;
          
          if (mode.indexOf("/CBC/") >= 0)
          {
            byte [] iv = getRandom(8);
            ivsp = new IvParameterSpec(iv);
          }
          else 
          {
            ivsp = null;
          }

          for (int len1=0; len1 < 1000; len1 += 177)
          {
            byte [] data1 = getRandom(len1);

            for (int len2=0;len2 < 30;len2 += 3)
            {
              byte [] data2 = getRandom(len2);

              for (int len3=1; len3 < 200; len3 += 19)
              {              
                if (mode.indexOf("NOPADDING") >= 0)
                {
                  int len = len1+len2+len3;
                  
                  if ((len = len % 8) != 0)
                  {
                    len3 += 8 - len;
                  }
                }
                
                byte [] data3 = getRandom(len3);

                // encrypt with CryptoServer 
                if (ivsp == null) c.init(Cipher.ENCRYPT_MODE, desKey);
                else              c.init(Cipher.ENCRYPT_MODE, desKey, ivsp);

                byte [] crypto = null;

                if (len1 != 0) crypto = cat(crypto, c.update(data1));
                if (len2 != 0) crypto = cat(crypto, c.update(data2));
                if (len3 != 0) crypto = cat(crypto, c.doFinal(data3));
                else           crypto = cat(crypto, c.doFinal());

                // decrypt with Sun Provider
                if (ivsp == null) c2.init(Cipher.DECRYPT_MODE, desKey2);
                else              c2.init(Cipher.DECRYPT_MODE, desKey2, ivsp);

                byte [] plain = c2.doFinal(crypto);
                
                // compare data
                byte [] data = cat(cat(data1, data2), data3);

                if (!Arrays.equals(data, plain))
                {
                  CryptoServerUtil.xtrace(plain);
                  CryptoServerUtil.xtrace(data);
                  System.out.println("Keysize="+keysize+", mode="+mode+", len="+len1+"-"+len2+"-"+len3);

                  throw new Exception("En-/Decryption failed");
                }

                // encrypt with Sun Provider 
                if (ivsp == null) c2.init(Cipher.ENCRYPT_MODE, desKey2);
                else              c2.init(Cipher.ENCRYPT_MODE, desKey2, ivsp);

                crypto = c2.doFinal(plain);

                // decrypt with CryptoServer
                if (ivsp == null) c.init(Cipher.DECRYPT_MODE, desKey);
                else              c.init(Cipher.DECRYPT_MODE, desKey, ivsp);

                plain = null;
                len3 = crypto.length - len1 - len2;

                if (len1 != 0) plain = cat(plain, c.update(crypto,0,len1));
                if (len2 != 0) plain = cat(plain, c.update(crypto,len1,len2));
                if (len3 != 0) plain = cat(plain, c.doFinal(crypto,len1+len2,len3));
                else           plain = cat(plain, c.doFinal());

                // compare data
                data = cat(cat(data1, data2), data3);
                
                if (!Arrays.equals(data, plain))
                {
                  CryptoServerUtil.xtrace(plain);
                  CryptoServerUtil.xtrace(data);
                  System.out.println("Keysize="+keysize+", mode="+mode+", len="+len1+"-"+len2+"-"+len3);

                  throw new Exception("En-/Decryption failed");
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
      if (length == 0)
        return null;
        
      byte[] buf = new byte[length];
      SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");      
      rng.nextBytes(buf);      
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
