package defaults;
import CryptoServerJCE.*;
import CryptoServerAPI.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.lang.*;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider 
 * for the CryptoServer Hardware Security Module.
 *
 * Retrieve provider information
 *
 */
public class prov_Info
{
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer JCE: prov_Info ---\n");
    
    String providerName = null;
    Provider provider = null;
    
    if (args.length > 1)
    {
      providerName = args[1];
    }
    
    Provider [] providers = Security.getProviders();
    System.out.println("List of all Providers:");
    for (int i=0; i<providers.length; i++)
      System.out.println("  " + providers[i].getName());

    if (providerName != null)
    {            
      System.out.println("Provider Name: " + providerName);
      
      // use given provider
      provider = Security.getProvider(providerName);
    }
    else
    {
      // use CryptoServer provider
      provider = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg"); 
      System.out.println("Device  : " + ((CryptoServerProvider)provider).getCryptoServer().getDevice());      
    }
    
    // show provider information
    System.out.println("\nProvider Information:");
    System.out.println("  Provider Name     : " + provider.getName());
    System.out.println("  Provider Version  : " + provider.getVersion());
    System.out.println("  Provider Info     : " + provider.getInfo());        
    
    // enumerate services
    System.out.println("\nServices:");
    
    Set<Provider.Service> services = provider.getServices();
    String header = String.format("%-32s %-32s", "Type", "Algorithm");
    System.out.println(header);
    System.out.println("---------------------------------------------------------------------------------");    
    
    for (Provider.Service element : services)
    {
      String line = String.format("%-32s %-32s", 
                                 element.getType(),                                 
                                 element.getAlgorithm()
                                 );
      
      System.out.println(line);
    }
        
    System.out.println("Done");
  }    
}
