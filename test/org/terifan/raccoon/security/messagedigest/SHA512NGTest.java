package org.terifan.raccoon.security.messagedigest;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import static org.testng.Assert.*;
import org.testng.annotations.Test;


public class SHA512NGTest
{
	@Test
	public void testVerifyResult() throws NoSuchAlgorithmException, DigestException
	{
		byte[] data = new byte[1024 * 1024];
		new Random(1).nextBytes(data);

		byte[] digest1 = MessageDigest.getInstance("SHA-512").digest(data);
		byte[] digest2 = new SHA512().digest(data);

		assertEquals(digest1, digest2);
	}
}
