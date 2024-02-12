package org.terifan.raccoon.security.cryptography.ciphermode;

import org.terifan.raccoon.security.cryptography.BlockCipher;


/**
 * This is an implementation of the XTS cipher mode with a modified IV initialization.
 * XTS source code is ported from TrueCrypt 7.0.
 */
public final class XTSCipherMode extends CipherMode
{
	private final static int BYTES_PER_BLOCK = 16;


	public XTSCipherMode()
	{
	}


	@Override
	public void encrypt(final byte[] aBuffer, int aOffset, final int aLength, final BlockCipher aCipher, long aStartDataUnitNo, final int aUnitSize, final int[] aBlockIV, BlockCipher aTweakCipher)
	{
		assert aUnitSize > 0;
		assert (aUnitSize & (BYTES_PER_BLOCK - 1)) == 0;
		assert (aLength & (BYTES_PER_BLOCK - 1)) == 0;
		assert aLength >= aUnitSize : aLength+" >= "+aUnitSize;
		assert (aLength % aUnitSize) == 0;
		assert aBlockIV.length == 4;

		byte[] whiteningValue = new byte[BYTES_PER_BLOCK];
		int numBlocks = aUnitSize / BYTES_PER_BLOCK;
		int numUnits = aLength / aUnitSize;

		for (int unitIndex = 0; unitIndex < numUnits; unitIndex++)
		{
			prepareIV(aBlockIV, aStartDataUnitNo++, whiteningValue, aTweakCipher);

			for (int block = 0; block < numBlocks; block++, aOffset += BYTES_PER_BLOCK)
			{
				xor(aBuffer, aOffset, BYTES_PER_BLOCK, whiteningValue, 0);

				aCipher.engineEncryptBlock(aBuffer, aOffset, aBuffer, aOffset);

				xor(aBuffer, aOffset, BYTES_PER_BLOCK, whiteningValue, 0);

				int finalCarry = ((whiteningValue[8 + 7] & 0x80) != 0) ? 135 : 0;

				putInt64LE(whiteningValue, 8, getInt64LE(whiteningValue, 8) << 1);

				if ((whiteningValue[7] & 0x80) != 0)
				{
					whiteningValue[8] |= 0x01;
				}

				putInt64LE(whiteningValue, 0, getInt64LE(whiteningValue, 0) << 1);

				whiteningValue[0] ^= finalCarry;
			}
		}
	}


	@Override
	public void decrypt(final byte[] aBuffer, int aOffset, final int aLength, final BlockCipher aCipher, long aStartDataUnitNo, final int aUnitSize, final int[] aBlockIV, BlockCipher aTweakCipher)
	{
		assert (aUnitSize & (BYTES_PER_BLOCK - 1)) == 0;
		assert (aLength & (BYTES_PER_BLOCK - 1)) == 0;
		assert aLength >= aUnitSize;
		assert (aLength % aUnitSize) == 0;
		assert aBlockIV.length == 4;

		byte[] whiteningValue = new byte[BYTES_PER_BLOCK];
		int numUnits = aLength / aUnitSize;
		int numBlocks = aUnitSize / BYTES_PER_BLOCK;

		for (int unitIndex = 0; unitIndex < numUnits; unitIndex++)
		{
			prepareIV(aBlockIV, aStartDataUnitNo++, whiteningValue, aTweakCipher);

			for (int block = 0; block < numBlocks; block++, aOffset += BYTES_PER_BLOCK)
			{
				xor(aBuffer, aOffset, BYTES_PER_BLOCK, whiteningValue, 0);

				aCipher.engineDecryptBlock(aBuffer, aOffset, aBuffer, aOffset);

				xor(aBuffer, aOffset, BYTES_PER_BLOCK, whiteningValue, 0);

				int finalCarry = (whiteningValue[8 + 7] & 0x80) != 0 ? 135 : 0;

				putInt64LE(whiteningValue, 8, getInt64LE(whiteningValue, 8) << 1);

				if ((whiteningValue[7] & 0x80) != 0)
				{
					whiteningValue[8] |= 0x01;
				}

				putInt64LE(whiteningValue, 0, getInt64LE(whiteningValue, 0) << 1);

				whiteningValue[0] ^= finalCarry;
			}
		}
	}


	// little endian
	private static void putInt64LE(byte[] aBuffer, int aOffset, long aValue)
	{
		aBuffer[aOffset] = (byte)(aValue);
		aBuffer[aOffset + 1] = (byte)(aValue >>> 8);
		aBuffer[aOffset + 2] = (byte)(aValue >>> 16);
		aBuffer[aOffset + 3] = (byte)(aValue >>> 24);
		aBuffer[aOffset + 4] = (byte)(aValue >>> 32);
		aBuffer[aOffset + 5] = (byte)(aValue >>> 40);
		aBuffer[aOffset + 6] = (byte)(aValue >>> 48);
		aBuffer[aOffset + 7] = (byte)(aValue >>> 56);
	}


	// little endian
	private static long getInt64LE(byte[] aBuffer, int aOffset)
	{
		return ((0xFF & aBuffer[aOffset]))
			+ ((0xFF & aBuffer[aOffset + 1]) << 8)
			+ ((0xFF & aBuffer[aOffset + 2]) << 16)
			+ ((long)(0xFF & aBuffer[aOffset + 3]) << 24)
			+ ((long)(0xFF & aBuffer[aOffset + 4]) << 32)
			+ ((long)(0xFF & aBuffer[aOffset + 5]) << 40)
			+ ((long)(0xFF & aBuffer[aOffset + 6]) << 48)
			+ ((long)(0xFF & aBuffer[aOffset + 7]) << 56);
	}
}
