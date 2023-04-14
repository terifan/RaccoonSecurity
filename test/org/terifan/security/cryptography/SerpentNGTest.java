package org.terifan.security.cryptography;

import static org.testng.Assert.*;
import org.testng.annotations.Test;


public class SerpentNGTest
{
	@Test
	public void testInitialized()
	{
		BlockCipher cipher = new Serpent();
		assertFalse(cipher.isInitialized());
		cipher.engineInit(new SecretKey(new byte[16]));
		assertTrue(cipher.isInitialized());
		cipher.engineReset();
		assertFalse(cipher.isInitialized());
		cipher.engineInit(new SecretKey(new byte[16]));
		assertTrue(cipher.isInitialized());
	}
}
