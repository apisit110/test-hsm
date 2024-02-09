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
 * Generate keys
 *
 */
public class key_Generate
{
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer JCE: key_Generate ---\n");
    
    final String desKeyName = "DES_gen_1";
    final String aesKeyName = "AES_gen_1";    
    final String rsaPrivateKeyName = "{U}RSA_prv_gen_1";
    final String ecPrivateKeyName = "EC_prv_gen_1";
    final String dsaPrivateKeyName = "DSA_prv_gen_1";
    
    CryptoServerProvider provider = null;
    
    try
    {
      // load provider
      provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");      
      System.out.println("Device  : " + provider.getCryptoServer().getDevice());
      
      // authenticate
      provider.loginPassword("JCE", "123456");
      
      // set key group (user has to be member of that group!)
      //provider.setProperty("KeyGroup", "MyGroup");

      // open key store                                                            
      KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
      ks.load(null, null);       
      
      // generate AES key
      System.out.println("generate AES key...");
      KeyGenerator kg = KeyGenerator.getInstance("AES", provider);    
      CryptoServerKeyGenParameterSpec kgp = new CryptoServerKeyGenParameterSpec();
      kgp.setExportable(true);
      // kgp.setPlainExportable(true);    
      kgp.setKeySize(256);    
      kg.init(kgp, null);
      SecretKey aesKey = kg.generateKey();
      ks.setKeyEntry(aesKeyName, aesKey, null, null);
      
      // generate DES key
      System.out.println("generate DES key...");
      kg = KeyGenerator.getInstance("DESede", provider);
      kg.init(112, null);
      SecretKey desKey = kg.generateKey();
      ks.setKeyEntry(desKeyName, desKey, null, null);
      
      // generate RSA key        
      System.out.println("generate RSA key...");
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
      kpg.initialize(2048, null);
      KeyPair rsaKeyPair = kpg.generateKeyPair();
      PrivateKey rsaPrivateKey = rsaKeyPair.getPrivate();
      PublicKey rsaPublicKey = rsaKeyPair.getPublic();    
      ks.setKeyEntry(rsaPrivateKeyName, rsaPrivateKey, null, provider.getDumyCertificateChain());          
      
      // generate ECDSA key
      System.out.println("generate EC key...");
      kpg = KeyPairGenerator.getInstance("EC", provider);    
      kpg.initialize(new ECGenParameterSpec("NIST-P256"));
      // kpg.initialize(256, null);    
      KeyPair ecKeyPair = kpg.generateKeyPair();
      PrivateKey ecPrivateKey = ecKeyPair.getPrivate();
      PublicKey ecPublicKey = ecKeyPair.getPublic();    
      ks.setKeyEntry(ecPrivateKeyName, ecPrivateKey, null, provider.getDumyCertificateChain());
      
      // generate DSA key
      System.out.println("generate DSA key...");
      kpg = KeyPairGenerator.getInstance("DSA", provider);    
      kpg.initialize(1024, null);    
      KeyPair dsaKeyPair = kpg.generateKeyPair();
      PrivateKey dsaPrivateKey = dsaKeyPair.getPrivate();
      PublicKey dsaPublicKey = dsaKeyPair.getPublic();    
      ks.setKeyEntry(dsaPrivateKeyName, dsaPrivateKey, null, provider.getDumyCertificateChain());
      
               
      // list keys    
      Enumeration<String> kl = ks.aliases();
      
      System.out.println(String.format("%-12s %-20s %s", "type", "name", "creation date"));          
      System.out.println("----------------------------------------------------------------------");
      
      while (kl.hasMoreElements())
      {
        String name = kl.nextElement();      
        Date date = ks.getCreationDate(name);
        String type;
        
        if (ks.isKeyEntry(name))       
          type = "Key";      
        else if (ks.isCertificateEntry(name))      
          type = "Certificate";      
        else       
          type = "???";      
        
        System.out.println(String.format("%-12s %-20s %s", type, name, date));      
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
}
