package defaults;
import CryptoServerJCE.*;
import CryptoServerAPI.*;
import java.io.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider 
 * for the CryptoServer Hardware Security Module.
 * 
 * Delete all keys
 *
 */
public class key_Delete
{
  public static void main(String[] args) throws Exception 
  {    
    System.out.println("\n--- Utimaco CryptoServer JCE: key_Delete ---\n");
    
    int nkeys = 0;
    
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
      System.out.println("KeyStore: " + ks.getType() + "\n");    
                 
      // list keys    
      Enumeration<String> kl = ks.aliases();
      
      while (kl.hasMoreElements())
      {
        String name = kl.nextElement();
        System.out.println("delete: " + name);
        ks.deleteEntry(name);
        nkeys++;
      }
      
      System.out.println("\n" + nkeys + " keys deleted");
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
