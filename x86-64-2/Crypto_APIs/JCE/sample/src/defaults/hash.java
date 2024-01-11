package defaults;

import CryptoServerJCE.*;
import CryptoServerAPI.*;

import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import java.security.*;
import java.util.Arrays;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider for the
 * CryptoServer Hardware Security Module.
 *
 * Creation of hash
 *
 */
public class hash {

	public static void main(String[] args) throws Exception {

		System.out.println("\n--- Utimaco CryptoServer JCE : hash ---\n");

		String modes[] = { "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "RMD-160", "SHA3-224",
				"SHA3-256", "SHA3-384", "SHA3-512" };

		CryptoServerProvider provCS = null;
		Provider provSun = null;

		try {
			// load providers
			provCS = new CryptoServerProvider(args.length > 0 ? args[0] : "CryptoServer.cfg");
			provSun = Security.getProvider("SUN");

			System.out.println("Device  : " + provCS.getCryptoServer().getDevice());

			// authenticate
			provCS.loginPassword("JCE", "123456");

			// create data
			byte[] data1 = "We are ".getBytes();
			byte[] data2 = "what we were ".getBytes();
			byte[] data3 = "waiting for !".getBytes();

			byte[] data = cat(cat(data1, data2), data3);

			for (String mode : modes) {
				System.out.println("\nmode: " + mode + "\n");

				// calculate hash on CryptoServer
				MessageDigest hashCS = MessageDigest.getInstance(mode, provCS);

				byte[] hashCSsingle = hashCS.digest(data);

				CryptoServerUtil.xtrace("hash CS", hashCSsingle);

				hashCS.update(data1);
				hashCS.update(data2);
				hashCS.update(data3);

				byte[] hashCSmulti = hashCS.digest();

				if (!Arrays.equals(hashCSsingle, hashCSmulti))
					throw new Exception("Hash compare failed");

				// calculate hash on SUN
				// SHA-224 and RMD-160 are not supported by the SUN provider
				if (mode == "SHA-224" || mode == "RMD-160" || mode == "SHA3-224" || mode == "SHA3-256"
						|| mode == "SHA3-384" || mode == "SHA3-512")
					continue;

				MessageDigest hashSun = MessageDigest.getInstance(mode, provSun);

				byte[] hashSunsingle = hashSun.digest(data);

				CryptoServerUtil.xtrace("hash Sun", hashSunsingle);

				hashSun.update(data1);
				hashSun.update(data2);
				hashSun.update(data3);

				byte[] hashSunmulti = hashSun.digest();

				if (!Arrays.equals(hashSunsingle, hashSunmulti))
					throw new Exception("Hash compare failed");

				// compare created hashes
				if (!Arrays.equals(hashCSsingle, hashSunsingle))
					throw new Exception("Hash compare failed");

				if (!Arrays.equals(hashCSmulti, hashSunmulti))
					throw new Exception("Hash compare failed");
			}
		} catch (Exception ex) {
			throw ex;
		} finally {
			// logoff
			if (provCS != null)
				provCS.logoff();
		}

		System.out.println("Done");
	}

	private static byte[] cat(byte[] a, byte[] b) {
		if (a == null)
			return (b);
		if (b == null)
			return (a);

		byte[] res = new byte[a.length + b.length];
		System.arraycopy(a, 0, res, 0, a.length);
		System.arraycopy(b, 0, res, a.length, b.length);

		return (res);
	}

}
