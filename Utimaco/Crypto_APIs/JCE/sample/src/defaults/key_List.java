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
 * List all keys 
 *
 */
public class key_List
{
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer JCE: key_List ---\n");
    
    CryptoServerProvider provider = null;
    
    try
    {
      provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");
      System.out.println("Device  : " + provider.getCryptoServer().getDevice());

      //provider.setProperty("KeyGroup", "test");
      
      // authenticate
      provider.loginPassword("JCE", "123456");
      
      // open key store                                                            
      KeyStore ks = KeyStore.getInstance("CryptoServer", provider);       
      ks.load(null, null);    
      System.out.println("KeyStore: " + ks.getType() + "\n");

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
