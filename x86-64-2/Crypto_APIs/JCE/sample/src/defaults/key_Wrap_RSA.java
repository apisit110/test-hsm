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
 * Import / Export one key encrypted with another (RSA) key
 * 
 */
public class key_Wrap_RSA
{
  private static class RSATestKey
  {
    final static String modulus = "B7F3893AAB150BAFECC1931097893C38751AD728DD56DEB8F1A41097755B5E0664FF32FD902B04EDCFD5E2EF8330FDF07C15F9C2229E53F71446EEDBC82BEA3D1679B2BBC07B269D0832D098B3478189CB1FD9F770ED5231EE9AA05BEBE2D0F13F4813F919EB8B3B14AEEE0EE22EDEB152CB5B5798712CDE28273B7E5AB232EB";
    final static String pExponent = "010001";
    final static String sExponent = "0C69C84467C01B524B5942B9D76800E2D47033BDC3B5F580A879C84ED8320AB5C6C1FBE8657EA9ADFC9CF3DBF2CFEF0AF7ECA9B6828C89A0FE42CD2292AEF7F6FB0B8BC61EAE635CE3ACAADACBB0609666266D28B2760483F169C05E672C5C88D2B5B0F66C6474AA7E75A3D526EFBD865D4CD8457DD8F9D31C4B095827C6B3AD";
    final static String primeP = "D19916EC3E718F393467AD608813306B58F763EF6F1A8FE1251AAAE720D1A6F0E552F95DE53C0FECDFFE0ED9E541FC00F83393C9E1B26789D3A779ACA9A5C905";
    final static String primeQ = "E0ACED5548DFF0A24147FEDE87B22505DC11FBC4F080C3E17A11BA588AE2A40AFCFDF352F9031F8F344E909C2ECCD912E2BA6B864C2DE6CFB4F50E03C17F0F2F";
    final static String coeff = "9EC636117E558F3A1C9E03E54A1FADD9F0A6728F34C5842B6F557D58C92BCB243FDB62AA9751B5AA24B4B5129B253ED97D3A69818C7AD2AA6483C2473C1E52F7";
    final static String pExpP = "9D165DC5C5AF1AA6C70E05355A06F7BD1CBA9D5DB0297A3845B4CCEDD8FD085F77A04E60FF139AE3EFA4DBC0974072FCCF08E8F4DF80F474A9FAD50881454D79";
    final static String pExpQ = "7332D781EA1AC0A4413AAC08E7A4C4ECEB38E151CA4B0BA499D56B29A914AA2DE42845D1DE51E6A5A39940F683DC8ED4EB21D0AE0C7360AC5149710525FA830B";
    
    public static Key getPrivateCRTKey(Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
      KeyFactory kf = KeyFactory.getInstance("RSA", provider);      
      
      RSAPrivateCrtKeySpec prvCrtKeySpec = new RSAPrivateCrtKeySpec(new BigInteger(modulus,16),
                                                                    new BigInteger(pExponent,16),
                                                                    new BigInteger(sExponent,16),
                                                                    new BigInteger(primeP,16),
                                                                    new BigInteger(primeQ,16),
                                                                    new BigInteger(pExpP,16),
                                                                    new BigInteger(pExpQ,16),
                                                                    new BigInteger(coeff,16));                                                                  
      return kf.generatePrivate(prvCrtKeySpec);
    }
    
    public static Key getPrivateKey(Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
      KeyFactory kf = KeyFactory.getInstance("RSA", provider);      
      
      RSAPrivateKeySpec prvKeySpec = new RSAPrivateKeySpec(new BigInteger(modulus,16),
                                                           new BigInteger(sExponent,16));                                                                    
      return kf.generatePrivate(prvKeySpec);
    }
    
    public static Key getPublicKey(Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
      KeyFactory kf = KeyFactory.getInstance("RSA", provider);      
      
      RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(new BigInteger(modulus,16),
                                                         new BigInteger(pExponent,16));                                                                 
      return kf.generatePublic(pubKeySpec);           
    }
  }
  
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer JCE: key_Wrap_RSA ---\n");
    
    final String aesKeyName = "AES_gen_1";    
    final String rsaPrivateKeyName = "RSA_prv_imp_1";
    final String rsaPublicKeyName = "RSA_pub_imp_1";   
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
      
      // import RSA key      
      CryptoServerRSAKeyGenParameterSpec rsaParam = new CryptoServerRSAKeyGenParameterSpec(1024, new BigInteger("010001", 16));
      rsaParam.setExportable(true);
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
      kpg.initialize(rsaParam, null);
      KeyPair keyPair = kpg.generateKeyPair();
      
      // ********************************************************************************
      // wrap / unwrap AES key with RSA key 
      // ********************************************************************************
      
      // generate AES key
      System.out.println("generate AES key...");
      
      KeyGenerator kg = KeyGenerator.getInstance("AES", provider);    
      CryptoServerKeyGenParameterSpec aesParam = new CryptoServerKeyGenParameterSpec(256);
      //aesParam.setExportable(true);
      aesParam.setPlainExportable(true);    
      kg.init(aesParam, null);
      SecretKey aesKey = kg.generateKey();
          
      // encrypt data
      Cipher testCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", provider);
      testCipher.init(Cipher.ENCRYPT_MODE, aesKey);
      byte [] crypto = testCipher.doFinal(testData);
          
      // export (wrap) AES key (encrypted with RSA key)
      System.out.println("export (wrap) AES key (encrypted with RSA key)...");
      
      Cipher wrapCipher = Cipher.getInstance("RSA/None/PKCS1Padding", provider);
      wrapCipher.init(Cipher.WRAP_MODE, keyPair.getPublic());
      byte [] keyBlob = wrapCipher.wrap(aesKey);
      
      CryptoServerUtil.xtrace("key blob", keyBlob);    
      
      // import (unwrap) encrypted AES key
      System.out.println("import (unwrap) encrypted AES key...");
      
      wrapCipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate());
      aesKey = (SecretKey)wrapCipher.unwrap(keyBlob, "AES", Cipher.SECRET_KEY);    
      
      // decrypt test data
      testCipher.init(Cipher.DECRYPT_MODE, aesKey);
      byte [] plain = testCipher.doFinal(crypto);
      
      CryptoServerUtil.xtrace("decrypted test data", plain);
      
      // compare result
      if (!Arrays.equals(plain, testData))
        throw new Exception("En-/Decryption failed");          
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
