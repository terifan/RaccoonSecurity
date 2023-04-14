package org.terifan.security.cryptography;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import org.testng.annotations.Test;


public class AESNGTest
{
	@Test
	public void testInitialized()
	{
		BlockCipher cipher = new AES();
		assertFalse(cipher.isInitialized());
		cipher.engineInit(new SecretKey(new byte[16]));
		assertTrue(cipher.isInitialized());
		cipher.engineReset();
		assertFalse(cipher.isInitialized());
		cipher.engineInit(new SecretKey(new byte[16]));
		assertTrue(cipher.isInitialized());
	}
}
