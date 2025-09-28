package org.terifan.raccoon.v0.security.messagedigest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;


/**
 * https://en.wikipedia.org/wiki/HKDF
 */
public class HKDF
{
	private final MessageDigest mMessageDigest;


	public HKDF(MessageDigest aMessageDigest)
	{
		mMessageDigest = aMessageDigest;
	}


	private byte[] hkdf_extract(byte[] salt, byte[] ikm)
	{
		HMAC hmac = new HMAC(mMessageDigest, salt);
		return hmac.digest(ikm);
	}


	private byte[] hkdf_expand(byte[] prk, byte[] info, int length) throws IOException
	{
		ByteArrayOutputStream okm = new ByteArrayOutputStream();
		byte[] tmp = new byte[0];
		for (int i = 1; okm.size() < length; i++)
		{
			HMAC hmac = new HMAC(mMessageDigest, prk);
			hmac.update(tmp);
			hmac.update(info);
			hmac.update((byte)i);
			tmp = hmac.digest();
			okm.write(tmp);
		}
		return Arrays.copyOfRange(okm.toByteArray(), 0, length);
	}


	public byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length) throws IOException
	{
		if (length > 255 * mMessageDigest.getDigestLength())
		{
			throw new IllegalStateException("Cannot expand a message to this length");
		}

		return hkdf_expand(hkdf_extract(salt, ikm), info, length);
	}


//	public static void main(String... args)
//	{
//		try
//		{
//			HKDF hkdf = new HKDF(new SHA256());
//
//			byte[] okm = hkdf.hkdf(
//				HexFormat.of().parseHex("000102030405060708090a0b0c"),
//				HexFormat.of().parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
//				HexFormat.of().parseHex("f0f1f2f3f4f5f6f7f8f9"),
//				42
//			);
//
//			System.out.println(HexFormat.of().formatHex(okm).equals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
//
//			okm = hkdf.hkdf(
//				HexFormat.of().parseHex(""),
//				HexFormat.of().parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
//				HexFormat.of().parseHex(""),
//				42
//			);
//
//			System.out.println(HexFormat.of().formatHex(okm).equals("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"));
//		}
//		catch (Throwable e)
//		{
//			e.printStackTrace(System.out);
//		}
//	}
}
