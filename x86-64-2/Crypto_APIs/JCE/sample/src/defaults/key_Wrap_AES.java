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
 * Export one key encrypted with another (AES) key
 *
 */
public class key_Wrap_AES
{ 
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer JCE: key_Wrap_AES ---\n");
    
    final String aesKeyName = "AES_imp_1";   
    final byte [] testData = "Hello World".getBytes();
    
    CryptoServerProvider provider = null;
    
    try
    {
      // load provider
      provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");      
      System.out.println("Device  : " + provider.getCryptoServer().getDevice());
      
      // authenticate
      provider.loginPassword("JCE", "123456");

      // open key store                                                            
      KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
      ks.load(null, null);
      
      // import AES key
      KeyGenerator kgAES = KeyGenerator.getInstance("AES", provider);
      kgAES.init(new CryptoServerKeyGenParameterSpec(256), null);
      SecretKey aesKEK = kgAES.generateKey();
      
      ks.setKeyEntry(aesKeyName, aesKEK, null, null);           
      aesKEK = (SecretKey)ks.getKey(aesKeyName, null);
      
      // ********************************************************************************
      // wrap / unwrap DES key with AES key 
      // ********************************************************************************
      
      // generate DES key
      System.out.println("\ngenerate DES key...");
      
      CryptoServerKeyGenParameterSpec desParam = new CryptoServerKeyGenParameterSpec(168);
      //desParam.setExportable(true);
      desParam.setPlainExportable(true);
      KeyGenerator kgDES = KeyGenerator.getInstance("DES", provider);    
      kgDES.init(desParam, null);
      SecretKey desKey = kgDES.generateKey();    
      
      // encrypt test data
      Cipher testCipher = Cipher.getInstance("DES/ECB/PKCS5Padding", provider);
      testCipher.init(Cipher.ENCRYPT_MODE, desKey);
      byte [] crypto = testCipher.doFinal(testData);
          
      // export (wrap) DES key (encrypted with AES key)
      System.out.println("export (wrap) DES key (encrypted with AES key)...");
      
      Cipher wrapCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", provider);
      wrapCipher.init(Cipher.WRAP_MODE, aesKEK);
      byte [] keyBlob = wrapCipher.wrap(desKey);
      
      CryptoServerUtil.xtrace("key blob", keyBlob);    
      
      // import (unwrap) encrypted DES key
      System.out.println("import (unwrap) encrypted DES key...");
      
      wrapCipher.init(Cipher.UNWRAP_MODE, aesKEK);
      desKey = (SecretKey)wrapCipher.unwrap(keyBlob, "DES", Cipher.SECRET_KEY);    
      
      // decrypt test data
      testCipher.init(Cipher.DECRYPT_MODE, desKey);
      byte [] plain = testCipher.doFinal(crypto);
      
      CryptoServerUtil.xtrace("decrypted test data", plain);
      
      // compare result
      if (!Arrays.equals(plain, testData))
        throw new Exception("En-/Decryption failed");
      
      // ********************************************************************************
      // wrap / unwrap DES key with AES key (with global export policy)
      // ********************************************************************************
      
      // generate DES key
      System.out.println("\ngenerate DES key...");
        
      provider.setProperty("Export", "1"); // set global export policy to "ALLOW"
      kgDES.init(168, null);
      desKey = kgDES.generateKey();
      
      // export (wrap) DES key (encrypted with AES key)
      System.out.println("export (wrap) DES key (encrypted with AES key)...");
      
      wrapCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", provider);
      wrapCipher.init(Cipher.WRAP_MODE, aesKEK);
      keyBlob = wrapCipher.wrap(desKey);
      
      CryptoServerUtil.xtrace("key blob", keyBlob);
      
      wrapCipher.init(Cipher.UNWRAP_MODE, aesKEK);
      desKey = (SecretKey)wrapCipher.unwrap(keyBlob, "DES", Cipher.SECRET_KEY);
      
      // encrypt test data
      testCipher.init(Cipher.ENCRYPT_MODE, desKey);
      crypto = testCipher.doFinal(testData);
      
      // decrypt test data
      testCipher.init(Cipher.DECRYPT_MODE, desKey);
      plain = testCipher.doFinal(crypto);
      
      CryptoServerUtil.xtrace("decrypted test data", plain);
      
      // compare result
      if (!Arrays.equals(plain, testData))
        throw new Exception("En-/Decryption failed");
      
      provider.setProperty("Export", "0"); // set global export policy to "DENY"
      
      // ********************************************************************************
      // wrap / unwrap RSA key with AES key 
      // ********************************************************************************
      
      // generate RSA key        
      System.out.println("\ngenerate RSA key...");
      
      CryptoServerRSAKeyGenParameterSpec rsaParam = new CryptoServerRSAKeyGenParameterSpec(1024, new BigInteger("010001", 16));
      rsaParam.setExportable(true);
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
      kpg.initialize(rsaParam, null);
      KeyPair keyPair = kpg.generateKeyPair();
      
      
      Signature sig = Signature.getInstance("SHA1withRSA", provider);
      Signature ver = Signature.getInstance("SHA1withRSA", provider);
      
      // export (wrap) RSA key (encrypted with AES key)
      System.out.println("export (wrap) RSA key (encrypted with AES key)...");
      
      wrapCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", provider);
      wrapCipher.init(Cipher.WRAP_MODE, aesKEK);
      keyBlob = wrapCipher.wrap(keyPair.getPrivate());
      
      CryptoServerUtil.xtrace("key blob", keyBlob);
      
      // import (unwrap) encrypted RSA key
      System.out.println("import (unwrap) encrypted RSA key...");
      
      wrapCipher.init(Cipher.UNWRAP_MODE, aesKEK);
      PrivateKey privateKey = (PrivateKey)wrapCipher.unwrap(keyBlob, "RSA", Cipher.PRIVATE_KEY);
      
      // sign test data
      System.out.println("sign test data...");
      
      sig.initSign(privateKey);
      sig.update(testData);
      byte[] signature = sig.sign();
      
      // verify test data
      System.out.println("verify signature...");
      
      ver.initVerify(keyPair.getPublic());
      ver.update(testData);
      
      if(!ver.verify(signature))
              throw new Exception("Signature verification failed");
      
      // ********************************************************************************
      // wrap / unwrap RSA key with AES key (with global export policy)
      // ********************************************************************************
      
      // generate RSA key
      System.out.println("\ngenerate RSA key...");
        
      provider.setProperty("Export", "1"); // set global export policy to "ALLOW"
      kpg.initialize(1024, null);
      keyPair = kpg.generateKeyPair();
      
      // export (wrap) RSA key (encrypted with AES key)
      System.out.println("export (wrap) RSA key (encrypted with AES key)...");
      
      wrapCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", provider);
      wrapCipher.init(Cipher.WRAP_MODE, aesKEK);
      keyBlob = wrapCipher.wrap(keyPair.getPrivate());
      
      CryptoServerUtil.xtrace("key blob", keyBlob);
      
      wrapCipher.init(Cipher.UNWRAP_MODE, aesKEK);
      privateKey = (PrivateKey)wrapCipher.unwrap(keyBlob, "RSA", Cipher.PRIVATE_KEY);
      
      // sign test data
      System.out.println("sign test data...");
      
      sig.initSign(privateKey);
      sig.update(testData);
      signature = sig.sign();
      
      // verify test data
      System.out.println("verify signature...");
      
      ver.initVerify(keyPair.getPublic());
      ver.update(testData);
      
      if(!ver.verify(signature))
              throw new Exception("Signature verification failed");
      
      provider.setProperty("Export", "0"); // set global export policy to "DENY"
        
      // ********************************************************************************
      // wrap / unwrap EC key with AES key 
      // ********************************************************************************
      
      // generate EC key    
      System.out.println("\ngenerate EC key...");
      
      CryptoServerECKeyGenParameterSpec ecParam = new CryptoServerECKeyGenParameterSpec("NIST-P384");
      ecParam.setExportable(true);
      kpg = KeyPairGenerator.getInstance("EC", provider);
      kpg.initialize(ecParam, null);
      keyPair = kpg.generateKeyPair();
      
      // export (wrap) private EC key (encrypted with AES key)
      System.out.println("export (wrap) EC key (encrypted with AES key)...");
      
      wrapCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", provider);
      wrapCipher.init(Cipher.WRAP_MODE, aesKEK);
      keyBlob = wrapCipher.wrap(keyPair.getPrivate());
      
      CryptoServerUtil.xtrace("key blob", keyBlob);
      
      // import (unwrap) encrypted EC key
      System.out.println("import (unwrap) encrypted EC key...");
      
      wrapCipher.init(Cipher.UNWRAP_MODE, aesKEK);
      privateKey = (PrivateKey)wrapCipher.unwrap(keyBlob, "EC", Cipher.PRIVATE_KEY);
      
      // sign test data
      System.out.println("sign test data...");
      
      sig = Signature.getInstance("SHA512withECDSA", provider);    
      sig.initSign(privateKey);              
      sig.update(testData);    
      signature = sig.sign();
      
      // verify test data    
      System.out.println("verify signature...");
      
      ver = Signature.getInstance("SHA512withECDSA", provider);
      ver.initVerify(keyPair.getPublic());
      ver.update(testData);
      
      if (!ver.verify(signature))
        throw new Exception("Signature verification failed");    
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
