package org.terifan.raccoon.security.messagedigest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import static org.testng.Assert.assertEquals;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;


public class HMACNGTest
{
	@Test(dataProvider = "hmac")
	public void testSomeMethod(MessageDigest aMessageDigest, String aExpected)
	{
		HMAC hmac = new HMAC(aMessageDigest, "password".getBytes());

		byte[] digest = hmac.digest("hello world".getBytes());

		String s = "";
		for (byte b : digest)
		{
			s += String.format("%02x", 0xff & b);
		}

		assertEquals(s, aExpected);
	}


	@DataProvider
	private Object[][] hmac() throws NoSuchAlgorithmException
	{
		return new Object[][]
		{
			{
				new SHA3(224),
				"645ea3a1e160e14af8669bcd7f9ca1fde7e900d44e06d0afe6b5db63"
			},
			{
				MessageDigest.getInstance("sha3-224"),
				"645ea3a1e160e14af8669bcd7f9ca1fde7e900d44e06d0afe6b5db63"
			},
			{
				new SHA3(256),
				"bfd488237a62f6371cbd1e32163343426cdbf59bf1bd434d1dfb93f59c6c07c7"
			},
			{
				MessageDigest.getInstance("sha3-256"),
				"bfd488237a62f6371cbd1e32163343426cdbf59bf1bd434d1dfb93f59c6c07c7"
			},
			{
				new SHA3(384),
				"0f32af89e364301076361a472d849c2e82e7e9e2ff2ad3e2bb33c9b9188fed843cd99274a60c038b6f3aa33b5fad777e"
			},
			{
				MessageDigest.getInstance("sha3-384"),
				"0f32af89e364301076361a472d849c2e82e7e9e2ff2ad3e2bb33c9b9188fed843cd99274a60c038b6f3aa33b5fad777e"
			},
			{
				new SHA3(512),
				"e5274661c40911c94499d916a8df5a439f51e0787e8a47367ed967367c5163a5a39e3d4985aa8f20400438091ea7bddaacaef7e92e3b7b5f400b436c97f8ebb1"
			},
			{
				MessageDigest.getInstance("sha3-512"),
				"e5274661c40911c94499d916a8df5a439f51e0787e8a47367ed967367c5163a5a39e3d4985aa8f20400438091ea7bddaacaef7e92e3b7b5f400b436c97f8ebb1"
			},
			{
				new Skein512(),
				"c1bf52ed5daad5e058fbba9660f2cdc5d67b7950c99e2b41f8b4d371c098da05a9a686378bd8ba6d61f586cfe3d1f2f579a4dab463ecf52c64760daf11bf2680"
			},
			{
				MessageDigest.getInstance("md5"),
				"40e2f652353b6575af3fae02a6b4ef58"
			},
			{
				new SHA1(),
				"2ffaf1b5b3f84a645cebbc9b72490c89cb9f519d"
			},
			{
				MessageDigest.getInstance("sha1"),
				"2ffaf1b5b3f84a645cebbc9b72490c89cb9f519d"
			},
			{
				MessageDigest.getInstance("sha224"),
				"abec176cfa8645a4f668790d7e28b35c24718af8c55305e7e1a22179"
			},
			{
				new SHA256(),
				"8f5f355441dc2722900f292004f3d8a83245ff4d6e3078a5b77a4d7a921eeae9"
			},
			{
				MessageDigest.getInstance("sha256"),
				"8f5f355441dc2722900f292004f3d8a83245ff4d6e3078a5b77a4d7a921eeae9"
			},
			{
				new SHA384(),
				"2fdfdd0cadb65096b51069147065ad31f9579b620c59d3ebfb17bf8f7eec4bf39ff78b826040f9a5d376382c1427d218"
			},
			{
				MessageDigest.getInstance("sha384"),
				"2fdfdd0cadb65096b51069147065ad31f9579b620c59d3ebfb17bf8f7eec4bf39ff78b826040f9a5d376382c1427d218"
			},
			{
				new SHA512(),
				"34851235db0e6eddf9ddace3e270e999584c7be93cb8d4b601a8c5d928b38a9f27254306acf3e9fb5765f1e49df81a29a26dd09eca6c10edbc072ee6a2f25485"
			},
			{
				MessageDigest.getInstance("sha512"),
				"34851235db0e6eddf9ddace3e270e999584c7be93cb8d4b601a8c5d928b38a9f27254306acf3e9fb5765f1e49df81a29a26dd09eca6c10edbc072ee6a2f25485"
			}
		};
	}
}
