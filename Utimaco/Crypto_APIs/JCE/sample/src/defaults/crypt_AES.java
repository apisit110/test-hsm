package defaults;
import CryptoServerJCE.*;
import CryptoServerAPI.*;
import javax.crypto.*;
import javax.crypto.spec.*;


import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider 
 * for the CryptoServer Hardware Security Module.
 * 
 * Test AES encryption / decryption with all keysizes and modes
 */
public class crypt_AES
{   
  public static void crypt_AES_CS_vs_CS(String[] args) throws Exception
  {
      System.out.println("\n--- Utimaco CryptoServer JCE - crypt_AES_cs_vs_cs ---\n");
      
      int sizes[] = { 128, 192, 256 };
      
      Algorithm modes[] = 
      {
            new Algorithm("AES/ECB/NOPADDING", null),     
            new Algorithm("AES/ECB/PKCS5Padding", null),
            new Algorithm("AES/ECB/ISO10126Padding", null),
            new Algorithm("AES/CBC/NOPADDING", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/CBC/PKCS5PADDING", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/CBC/ISO10126PADDING", new IvParameterSpec(getRandom(16))),
            // CryptoServerGCMParameterSpec parameters: tagLength in bits, IV, additional authentication data
            new Algorithm("AES/GCM/NOPADDING", new CryptoServerGCMParameterSpec(64, getRandom(16), getRandom(16))),
            new Algorithm("AES/OFB128/NOPADDING", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/OFB128/PKCS5Padding", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/OFB128/ISO10126PADDING", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/OFB/NOPADDING", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/OFB/PKCS5Padding", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/OFB/ISO10126PADDING", new IvParameterSpec(getRandom(16))),
      };
      

      CryptoServerProvider provider = null;
      
      try
      {    
        // load provider    
        provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");      
        System.out.println("Device  : " + provider.getCryptoServer().getDevice());
        
        // authenticate
        provider.loginPassword("JCE", "123456");    

        for (int keysize : sizes)
        {
          System.out.println("keysize: " + keysize);
          
          // Generate AES aesKey      
          CryptoServerKeyGenParameterSpec aesParam = new CryptoServerKeyGenParameterSpec(keysize);                 
          aesParam.setPlainExportable(true);
          
          KeyGenerator kg = KeyGenerator.getInstance("AES", provider);
          kg.init(aesParam, null);
          SecretKey aesKey = kg.generateKey();

          // for all modes      
          for (Algorithm mode : modes)
          {  
            String algo = mode.algo;
            System.out.println("algo: " + algo);
            
            Cipher c = Cipher.getInstance(algo,provider);

            for (int len1=0; len1 < 1000; len1 += 177)
            {          
              for (int len2=1; len2 < 30; len2 += 3)
              {
                for (int len3=0; len3 < 200; len3 += 19)
                {
                  if (algo.indexOf("/OFB") < 0 && algo.indexOf("/GCM") < 0 && algo.indexOf("NOPADDING") >= 0)
                  {
                    int len = len1+len2+len3;
                    
                    if ((len = len % 16) != 0)
                    {
                      len2 += 16 - len;  // add to 2nd block to ensure that 3rd can be empty!
                    }
                  }
                  
                  byte [] data1 = getRandom(len1);
                  byte [] data2 = getRandom(len2);
                  byte [] data3 = getRandom(len3);

                  // encrypt with CryptoServer
                  if (mode.param == null) 
                      c.init(Cipher.ENCRYPT_MODE, aesKey);
                  else             
                      c.init(Cipher.ENCRYPT_MODE, aesKey, mode.param);
                  
                  byte [] crypto = null;

                  if (len1 != 0) crypto = cat(crypto, c.update(data1));
                  if (len2 != 0) crypto = cat(crypto, c.update(data2));
                  if (len3 != 0) crypto = cat(crypto, c.doFinal(data3));
                  else           crypto = cat(crypto, c.doFinal());
                  
                  // decrypt with CryptoServer
                  if (mode.param == null) 
                    c.init(Cipher.DECRYPT_MODE, aesKey);
                  else             
                    c.init(Cipher.DECRYPT_MODE, aesKey, mode.param);

                  byte [] plain = null;
                  len2 = crypto.length - len1 - len3;

                  if (len1 != 0) plain = cat(plain, c.update(crypto,0,len1));
                  if (len2 != 0) plain = cat(plain, c.update(crypto,len1,len2));
                  if (len3 != 0) plain = cat(plain, c.doFinal(crypto,len1+len2,len3));
                  else           plain = cat(plain, c.doFinal());

                  // compare data
                  byte []data = cat(cat(data1, data2), data3);
                  
                  if (!Arrays.equals(data, plain))
                  {
                    CryptoServerUtil.xtrace(plain);
                    CryptoServerUtil.xtrace(data);
                    System.out.println("Keysize="+keysize+", mode="+mode.algo+", len="+len1+"-"+len2+"-"+len3);

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
  
  public static void crypt_AES_CS_vs_SUN_or_IBM(String[] args) throws Exception
  {
      System.out.println("\n--- Utimaco CryptoServer JCE - crypt_AES_CS_vs_SUN_or_IBM ---\n");
      
      String PROV_CIPHER;
      
      if (System.getProperty("os.name").indexOf("AIX") >= 0)
        PROV_CIPHER  = "IBMJCE";
      else 
        PROV_CIPHER  = "SunJCE";
      
      int sizes[] = { 128, 192, 256 };
      
      Algorithm modes[] = 
      {
            new Algorithm("AES/ECB/NOPADDING", null),     
            new Algorithm("AES/ECB/PKCS5Padding", null),
            new Algorithm("AES/ECB/ISO10126Padding", null),
            new Algorithm("AES/CBC/NOPADDING", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/CBC/PKCS5PADDING", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/CBC/ISO10126PADDING", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/OFB128/NOPADDING", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/OFB128/PKCS5Padding", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/OFB128/ISO10126PADDING", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/OFB/NOPADDING", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/OFB/PKCS5Padding", new IvParameterSpec(getRandom(16))),
            new Algorithm("AES/OFB/ISO10126PADDING", new IvParameterSpec(getRandom(16))),
      };
      
      CryptoServerProvider provider = null;
      
      try
      {    
        // load provider    
        provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");      
        System.out.println("Device  : " + provider.getCryptoServer().getDevice());
        
        // authenticate
        provider.loginPassword("JCE", "123456");    

        for (int keysize : sizes)
        {
          System.out.println("keysize: " + keysize);
          
          // Generate AES aesKey      
          CryptoServerKeyGenParameterSpec aesParam = new CryptoServerKeyGenParameterSpec(keysize);                 
          aesParam.setPlainExportable(true);
          
          KeyGenerator kg = KeyGenerator.getInstance("AES", provider);
          kg.init(aesParam, null);
          SecretKey aesKey = kg.generateKey();

          // export aesKey
          SecretKeyFactory kf = SecretKeyFactory.getInstance("AES",provider);
          SecretKeySpec aesKeySpec = (SecretKeySpec)kf.getKeySpec(aesKey,SecretKeySpec.class);
          
          // for all modes      
          for (Algorithm mode : modes)
          {  
            String algo = mode.algo;
            System.out.println("algo: " + algo);
            
            Cipher c = Cipher.getInstance(algo,provider);
            Cipher c2 = Cipher.getInstance(algo, PROV_CIPHER);
            
            for (int len1=0; len1 < 1000; len1 += 177)
            {          
              byte [] data1 = getRandom(len1);
             
              for (int len2=0; len2 < 30; len2 += 3)
              {
                byte [] data2 = getRandom(len2);

                for (int len3=1; len3 < 200; len3 += 19)
                {
                  if (algo.indexOf("OFB") < 0 && algo.indexOf("NOPADDING") >= 0)
                  {
                    int len = len1+len2+len3;
                    
                    if ((len = len % 16) != 0)
                    {
                      len3 += 16 - len;
                    }
                  }
                  
                  byte [] data3 = getRandom(len3);              

                  // encrypt with CryptoServer
                  if (mode.param == null) 
                      c.init(Cipher.ENCRYPT_MODE, aesKey);
                  else             
                      c.init(Cipher.ENCRYPT_MODE, aesKey, mode.param);
                  
                  byte [] crypto = null;

                  if (len1 != 0) crypto = cat(crypto, c.update(data1));
                  if (len2 != 0) crypto = cat(crypto, c.update(data2));
                  if (len3 != 0) crypto = cat(crypto, c.doFinal(data3));
                  else           crypto = cat(crypto, c.doFinal());
                  
                  // decrypt with Sun Provider / IBM
                  if (mode.param == null) 
                    c2.init(Cipher.DECRYPT_MODE,aesKeySpec);
                  else             
                    c2.init(Cipher.DECRYPT_MODE,aesKeySpec,mode.param);

                  byte [] plain = c2.doFinal(crypto);
                  
                  // compare data
                  byte [] data = cat(cat(data1, data2), data3);

                  if (!Arrays.equals(data, plain))
                  {
                    CryptoServerUtil.xtrace(plain);
                    CryptoServerUtil.xtrace(data);
                    System.out.println("Keysize="+keysize+", mode="+mode.algo+", len="+len1+"-"+len2+"-"+len3);

                    throw new Exception("En-/Decryption failed");
                  }

                  // encrypt with Sun Provider / IBM
                  if (mode.param == null) 
                    c2.init(Cipher.ENCRYPT_MODE, aesKeySpec);
                  else             
                    c2.init(Cipher.ENCRYPT_MODE, aesKeySpec, mode.param);

                  crypto = c2.doFinal(plain);

                  // decrypt with CryptoServer
                  if (mode.param == null) 
                    c.init(Cipher.DECRYPT_MODE, aesKey);
                  else             
                    c.init(Cipher.DECRYPT_MODE, aesKey, mode.param);

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
                    System.out.println("Keysize="+keysize+", mode="+mode.algo+", len="+len1+"-"+len2+"-"+len3);

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
  
  public static void main(String[] args) throws Exception 
  {
      crypt_AES_CS_vs_CS(args);
      crypt_AES_CS_vs_SUN_or_IBM(args);
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
