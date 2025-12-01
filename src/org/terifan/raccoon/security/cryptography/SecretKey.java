package org.terifan.raccoon.security.cryptography;

import java.nio.ByteBuffer;
import java.util.Arrays;


public final class SecretKey
{
	private transient final byte[] mKeyBytes;


	public SecretKey(byte[] aKeyBytes)
	{
		mKeyBytes = aKeyBytes.clone();
	}


	public SecretKey(int... aParts)
	{
		mKeyBytes = new byte[4 * aParts.length];
		ByteBuffer bb = ByteBuffer.wrap(mKeyBytes);
		for (int tmp : aParts)
		{
			bb.putInt(tmp);
		}
	}


	public SecretKey(long... aParts)
	{
		mKeyBytes = new byte[8 * aParts.length];
		ByteBuffer bb = ByteBuffer.wrap(mKeyBytes);
		for (long tmp : aParts)
		{
			bb.putLong(tmp);
		}
	}


	byte[] bytes()
	{
		return mKeyBytes;
	}


	public void reset()
	{
		Arrays.fill(mKeyBytes, (byte)0);
	}
}