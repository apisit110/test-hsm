package defaults;
import CryptoServerJCE.*;
import CryptoServerAPI.*;

import javax.crypto.*;

import java.security.*;
import java.util.Arrays;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider 
 * for the CryptoServer Hardware Security Module.
 *
 *  Creation of hash message authentication code (HMAC) with AES
 *
 */
public class hmac_AES {

	public static void main(String[] args) throws Exception 
	{
		System.out.println("\n--- Utimaco CryptoServer JCE : hmac_AES ---\n");
		
		int sizes[] = { 128, 192, 256 };
	    
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
	    Provider provSun = null;
	    
        SecretKey aesKey;
        
        KeyGenerator kg;
	    
	    try
	    {
	    	// load providers
	    	provCS = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");    
	    	provSun = Security.getProvider("SunJCE");
	    	
	        System.out.println("Device  : " + provCS.getCryptoServer().getDevice());
	        
	        // authenticate
	        provCS.loginPassword("JCE", "123456");
	        
	        for (int keysize : sizes)
            {     
	            System.out.println("keysize: " + keysize);
	            
	            // create key object
	            kg = KeyGenerator.getInstance("AES", provSun);
	            kg.init(keysize);
	            aesKey = kg.generateKey();
	        
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
                
	                hmacCS.init(aesKey);
	                byte [] hmac1CS = hmacCS.doFinal(data);
                
	                CryptoServerUtil.xtrace("hmac CS", hmac1CS);
                
	                // calculate HMAC (demonstrate chunked operation)
	                hmacCS.init(aesKey);
	                hmacCS.update(data1);
	                hmacCS.update(data2);    
	                hmacCS.update(data3);    
	                byte [] hmac2CS = hmacCS.doFinal();
                
	                if (!Arrays.equals(hmac1CS, hmac2CS)) 
	                    throw new Exception("Hmac compare failed");
                
	                // calculate HMAC on SunJCE
                
                        // SHA224 and RMD160 are not supported by the SunJCE provider
	                if(mode == "HmacSHA224" || mode == "HmacRMD160" || mode == "HmacSHA3-224" 
	                		|| mode == "HmacSHA3-256" || mode == "HmacSHA3-384" || mode == "HmacSHA3-512")
	                    continue;
                
	                Mac hmacSun = Mac.getInstance(mode, provSun);
                
	                hmacSun.init(aesKey);
	                byte [] hmac1Sun = hmacSun.doFinal(data);
                
	                CryptoServerUtil.xtrace("hmac SunJCE", hmac1Sun);
                
	                // calculate HMAC on SunJCE (demonstrate chunked operation)
	                hmacSun.init(aesKey);
	                hmacSun.update(data1);
	                hmacSun.update(data2);    
	                hmacSun.update(data3);    
	                byte [] hmac2Sun = hmacSun.doFinal();
                
	                // compare created Hmacs
	                if (!Arrays.equals(hmac1CS, hmac1Sun)) 
	                    throw new Exception("Hmac compare failed");
                
	                if (!Arrays.equals(hmac2CS, hmac2Sun)) 
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
