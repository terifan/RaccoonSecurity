package org.terifan.raccoon.security.cryptography.ciphermode;

import org.terifan.raccoon.security.cryptography.BlockCipher;


public final class OFBCipherMode extends CipherMode
{
	private final static int BYTES_PER_BLOCK = 16;


	public OFBCipherMode()
	{
	}


	@Override
	public void encrypt(final byte[] aBuffer, int aOffset, final int aLength, final BlockCipher aCipher, long aStartDataUnitNo, final int aUnitSize, final int[] aBlockIV, BlockCipher aTweakCipher)
	{
		assert (aUnitSize & (BYTES_PER_BLOCK - 1)) == 0;
		assert (aLength & (BYTES_PER_BLOCK - 1)) == 0;
		assert aLength >= aUnitSize : aLength + " >= " + aUnitSize;
		assert (aLength % aUnitSize) == 0 : aLength + " % " + aUnitSize;

		byte[] iv = new byte[BYTES_PER_BLOCK]; // IV
		int numUnits = aLength / aUnitSize;
		int numBlocks = aUnitSize / BYTES_PER_BLOCK;

		for (int unitIndex = 0; unitIndex < numUnits; unitIndex++)
		{
			prepareIV(aBlockIV, aStartDataUnitNo++, iv, aTweakCipher);

			for (int block = 0; block < numBlocks; block++, aOffset += BYTES_PER_BLOCK)
			{
				aCipher.engineEncryptBlock(iv, 0, iv, 0);

				xor(aBuffer, aOffset, BYTES_PER_BLOCK, iv, 0);
			}
		}
	}


	@Override
	public void decrypt(final byte[] aBuffer, int aOffset, final int aLength, final BlockCipher aCipher, long aStartDataUnitNo, final int aUnitSize, final int[] aBlockIV, BlockCipher aTweakCipher)
	{
		assert (aUnitSize & (BYTES_PER_BLOCK - 1)) == 0;
		assert (aLength & (BYTES_PER_BLOCK - 1)) == 0;
		assert aLength >= aUnitSize : aLength + " >= " + aUnitSize;
		assert (aLength % aUnitSize) == 0 : aLength + " % " + aUnitSize;

		byte[] iv = new byte[BYTES_PER_BLOCK + BYTES_PER_BLOCK]; // IV + next IV
		int numUnits = aLength / aUnitSize;
		int numBlocks = aUnitSize / BYTES_PER_BLOCK;

		for (int unitIndex = 0; unitIndex < numUnits; unitIndex++)
		{
			prepareIV(aBlockIV, aStartDataUnitNo++, iv, aTweakCipher);

			for (int block = 0, ivOffset = 0; block < numBlocks; block++, ivOffset = BYTES_PER_BLOCK - ivOffset, aOffset += BYTES_PER_BLOCK)
			{
				aCipher.engineEncryptBlock(iv, 0, iv, 0);

				xor(aBuffer, aOffset, BYTES_PER_BLOCK, iv, 0);
			}
		}
	}
}
