package org.terifan.raccoon.security.messagedigest;


public final class Fletcher4
{
	/**
	 * note: this implementation might compute beyond the end of the buffer since it operates on four bytes at a time!
	 */
	public static int[] hash128(byte[] aData, int aOffset, int aLength, long aSeed)
	{
		int a = (int)(aSeed >>> 32);
		int b = (int)(aSeed >>> 24);
		int c = (int)(aSeed >>> 8);
		int d = (int)(aSeed);

		for (int i = 0; i < aLength; i += 4, aOffset += 4)
		{
			a += ((aData[aOffset] & 255) << 24) + ((aData[aOffset + 1] & 255) << 16) + ((aData[aOffset + 2] & 255) << 8) + (aData[aOffset + 3] & 255);
			b += a;
			c += b;
			d += c;
		}

		return new int[]
		{
			a, b, c, d
		};
	}
}
