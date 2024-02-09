package defaults;
import CryptoServerJCE.*;
import CryptoServerAPI.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider 
 * for the CryptoServer Hardware Security Module.
 *
 * Login methods
 *
 */
public class prov_Login
{ 
  public static SecretKey generateKey(Provider provider) throws Exception
  {
    KeyGenerator kg = KeyGenerator.getInstance("AES", provider);    
    CryptoServerKeyGenParameterSpec kgp = new CryptoServerKeyGenParameterSpec();      
    kgp.setKeySize(256);    
    kg.init(kgp, null);
    return kg.generateKey();        
  }
  
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer JCE: prov_Login ---\n");
    
    String providerName = null;
    Provider provider = null;
    
    if (args.length > 1)
      providerName = args[1];          

    Provider [] providers = Security.getProviders();
    System.out.println("List of all Providers:");
    for (int i=0; i<providers.length; i++)
      System.out.println("  " + providers[i].getName());
    
    try
    {
      if (providerName == null)
      {
        // load provider    
        provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");
        System.out.println("Device  : " + ((CryptoServerProvider)provider).getCryptoServer().getDevice());
        
        System.out.println("\nLogin to CryptoServer...");
              
        switch (1)
        {
          case 1:
            // password authentication
            ((CryptoServerProvider)provider).loginPassword("JCE", "123456");      
            break;
          
          case 2:          
            // signature authentication with plain text key file
            ((CryptoServerProvider)provider).loginSign("JCE_RSA", "rsa.key", null);
            break;
          
          case 3:
            // signature authentication with password-encrypted key file
            ((CryptoServerProvider)provider).loginSign("JCE_RSA", "rsa_enc.key", "utimaco");
            break;
        }
        
        System.out.println("OK");
        
        System.out.println("\nGenerate key...");
        SecretKey key = generateKey(provider);
        System.out.println("OK");
        
        System.out.println("\nStore key in key store...");
        KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
        ks.load(null, null);
        ks.setKeyEntry("TEST_KEY", key, null, null);
        System.out.println("OK");
      }
      else
      {      
        provider = Security.getProvider(providerName);
        
        if (provider == null)
          throw new Exception("Invalid provider: " + providerName);
        
        if (provider.getName().equals("CryptoServer"))
        {
          // load key store (implies authentication of default user)
          System.out.println("\nAccessing key store...");      
          KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
          ks.load(null, "123456".toCharArray());
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
      if (  provider != null
         && provider instanceof CryptoServerProvider
         )
        ((CryptoServerProvider)provider).logoff();
    }
    
    System.out.println("Done");
  }
}
