package org.terifan.raccoon.security.messagedigest;

import java.security.DigestException;


/**
 * FIPS-180-2 compliant SHA-512 implementation<p>
 *
 * Implementation from bouncycastle.org
 *
 * Copyright (c) 2000-2006 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)
 */
public final class SHA512 extends SHABase implements Cloneable
{
	private final int mOutputLength;


	public SHA512()
	{
		this(512);
	}


	/**
	 * Constructor for cloning
	 */
	public SHA512(SHA512 aBase)
	{
		super(aBase.mOutputLength == 512 ? "sha-512" : "sha-512/" + aBase.mOutputLength, aBase);

		mOutputLength = aBase.mOutputLength;
	}


	/**
	 *
	 * @param aOutputLength the output length can be 224, 256 or 512 bits.
	 */
	public SHA512(int aOutputLength)
	{
		super(aOutputLength == 512 ? "sha-512" : "sha-512/" + aOutputLength);

		if (aOutputLength != 512 && aOutputLength != 256 && aOutputLength != 224)
		{
			throw new IllegalArgumentException("Output length can be 224, 256 or 512 bits.");
		}

		mOutputLength = aOutputLength;

		engineReset();
	}


	@Override
	protected int engineDigest(byte[] out, int outOff, int len) throws DigestException
	{
		if (out.length - outOff < mOutputLength / 8)
		{
			throw new DigestException("Buffer too short.");
		}

		finish();

		unpackWord(H1, out, outOff);
		unpackWord(H2, out, outOff + 8);
		unpackWord(H3, out, outOff + 16);

		if (mOutputLength == 224)
		{
			unpackInt(H4, out, outOff + 24);
		}
		else
		{
			unpackWord(H4, out, outOff + 24);
		}

		if (mOutputLength == 512)
		{
			unpackWord(H5, out, outOff + 32);
			unpackWord(H6, out, outOff + 40);
			unpackWord(H7, out, outOff + 48);
			unpackWord(H8, out, outOff + 56);
		}

		reset();

		return mOutputLength;
	}


	@Override
	protected int engineGetDigestLength()
	{
		return mOutputLength / 8;
	}


	@Override
	protected void engineReset()
	{
		baseReset();

		/*
		 * https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf
		 */
		switch (mOutputLength)
		{
			case 512:
				// SHA-512 initial hash value
				// he first 64 bits of the fractional parts of the square roots of the first eight prime numbers
				H1 = 0x6a09e667f3bcc908L;
				H2 = 0xbb67ae8584caa73bL;
				H3 = 0x3c6ef372fe94f82bL;
				H4 = 0xa54ff53a5f1d36f1L;
				H5 = 0x510e527fade682d1L;
				H6 = 0x9b05688c2b3e6c1fL;
				H7 = 0x1f83d9abfb41bd6bL;
				H8 = 0x5be0cd19137e2179L;
				break;
			case 256:
				H1 = 0x22312194FC2BF72CL;
				H2 = 0x9F555FA3C84C64C2L;
				H3 = 0x2393B86B6F53B151L;
				H4 = 0x963877195940EABDL;
				H5 = 0x96283EE2A88EFFE3L;
				H6 = 0xBE5E1E2553863992L;
				H7 = 0x2B0199FC2C85B8AAL;
				H8 = 0x0EB72DDC81C52CA2L;
				break;
			case 224:
				H1 = 0x8C3D37C819544DA2L;
				H2 = 0x73E1996689DCD4D6L;
				H3 = 0x1DFAB7AE32FF9C82L;
				H4 = 0x679DD514582F9FCFL;
				H5 = 0x0F6D2B697BD44DA8L;
				H6 = 0x77E36F7304C48942L;
				H7 = 0x3F9D85A86A1D36C8L;
				H8 = 0x1112E6AD91D692A1L;
				break;
		}
	}


	@Override
	public String toString()
	{
		return mOutputLength == 512 ? "sha-512" : "sha-512/" + mOutputLength;
	}


	@Override
	public SHA512 clone()
	{
		return new SHA512(this);
	}


	public static int[] hash128(byte[] aData, int aOffset, int aLength, long aSeed)
	{
		SHA512 instance = new SHA512();
		instance.update((byte)(aSeed >>> 56));
		instance.update((byte)(aSeed >> 48));
		instance.update((byte)(aSeed >> 40));
		instance.update((byte)(aSeed >> 32));
		instance.update((byte)(aSeed >> 24));
		instance.update((byte)(aSeed >> 16));
		instance.update((byte)(aSeed >> 8));
		instance.update((byte)(aSeed));
		instance.update(aData, aOffset, aLength);
		byte[] tmp = instance.engineDigest();
		int[] result = new int[4];
		for (int i = 0, j = 0; i < 16; i += 4)
		{
			result[j++] = ((tmp[i] & 255) << 24) + ((tmp[i + 1] & 255) << 16) + ((tmp[i + 2] & 255) << 8) + (tmp[i + 3] & 255);
		}
		return result;
	}
}
