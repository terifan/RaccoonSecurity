package org.terifan.raccoon.security.cryptography.util;

import java.util.Arrays;
import org.terifan.raccoon.security.messagedigest.SHA512;
import org.terifan.raccoon.security.random.SecureRandom;


/**
 * Methods used to pad blocks, i.e. make them a multiple of a specified unit size.
 */
public class BlockPadding
{
	private static class Holder
	{
		final static SecureRandom PRNG = new SecureRandom(System.currentTimeMillis() ^ System.nanoTime() ^ Arrays.hashCode(new SHA512().digest(System.getProperties().toString().getBytes())));
	}


	/**
	 * Pads the array provided with counter values.
	 */
	public static byte[] counterPadding(byte[] aData, int aUnitSize)
	{
		if ((aData.length % aUnitSize) == 0)
		{
			return aData;
		}

		byte[] paddedBlock = Arrays.copyOfRange(aData, 0, (aData.length + aUnitSize - 1) / aUnitSize * aUnitSize);
		for (int i = aData.length, j = 0; i < paddedBlock.length; i++)
		{
			paddedBlock[i] = (byte)j++;
		}

		return paddedBlock;
	}


	/**
	 * Pads the array provided with random values.
	 */
	public static byte[] randomPadding(byte[] aData, int aUnitSize)
	{
		if ((aData.length % aUnitSize) == 0)
		{
			return aData;
		}

		byte[] paddedBlock = Arrays.copyOfRange(aData, 0, (aData.length + aUnitSize - 1) / aUnitSize * aUnitSize);

		byte[] padding = Holder.PRNG.bytes(paddedBlock.length - aData.length).toArray();

		System.arraycopy(padding, 0, paddedBlock, aData.length, padding.length);

		return paddedBlock;
	}
}
