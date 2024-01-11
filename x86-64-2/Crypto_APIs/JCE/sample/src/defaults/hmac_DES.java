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
 *  Creation of hash message authentication code (HMAC) with DES
 *
 */
public class hmac_DES {
	
	public static void main(String[] args) throws Exception 
	{
		System.out.println("\n--- Utimaco CryptoServer JCE : hmac_DES ---\n");
		
		int sizes[] = { 56, 112, 168 };
	    
	    String modes[] = { "HmacMD5",
	    				   "HmacSHA1", 
	    				   "HmacSHA224",
	    				   "HmacSHA256",
	    				   "HmacSHA384",
	    				   "HmacSHA512",
	    				   "HmacRMD160",
	    				   "HmacSHA3-224",
	    				   "HmacSHA3-256",
	    				   "HmacSHA3-384",
	    				   "HmacSHA3-512"};
	    
	    CryptoServerProvider provCS = null;
        
        KeyGenerator kg;
        SecretKey desKey;
	    
	    try
	    {
	    	// load providers
	    	provCS = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");    
	    	
	        System.out.println("Device  : " + provCS.getCryptoServer().getDevice());
	        
	        // authenticate
	        provCS.loginPassword("JCE", "123456");
	        
	        for (int keysize : sizes)
	        {
	            System.out.println("keysize: " + keysize);
                String algorithm = (keysize == 56) ? "DES" : "DESede";
                
                // create key object
                kg = KeyGenerator.getInstance(algorithm, provCS);
                kg.init(new CryptoServerKeyGenParameterSpec(keysize), null);
                desKey = kg.generateKey();
                
                for (String mode : modes)
                {
                    System.out.println("\nmode: " + mode + "\n");                 
                    
                    // create data
                    byte [] data1 = "We are ".getBytes();
                    byte [] data2 = "what we were ".getBytes();
                    byte [] data3 = "waiting for !".getBytes();
                    
                    byte [] data = cat(cat(data1, data2), data3);
                    
                    // calculate HMAC on CryptoServer      
                    Mac hmacCS = Mac.getInstance(mode, provCS);
                    
                    hmacCS.init(desKey);
                    byte [] hmac1CS = hmacCS.doFinal(data);
                    
                    CryptoServerUtil.xtrace("hmac", hmac1CS);
                    
                    // calculate HMAC (demonstrate chunked operation)
                    hmacCS.init(desKey);
                    hmacCS.update(data1);
                    hmacCS.update(data2);    
                    hmacCS.update(data3);    
                    byte [] hmac2CS = hmacCS.doFinal();
                    
                    if (!Arrays.equals(hmac1CS, hmac2CS)) 
                      throw new Exception("Hmac compare failed");
                    
                }
	        }
	    	
	    }catch (Exception ex){
	        throw ex;
	    }finally{
	        // logoff
	        if (provCS != null)
	        	provCS.logoff();
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
