package org.terifan.raccoon.security.cryptography.ciphermode;

import org.terifan.raccoon.security.cryptography.BlockCipher;


public final class PCBCCipherMode extends CipherMode
{
	private final static int BYTES_PER_BLOCK = 16;


	public PCBCCipherMode()
	{
	}


	@Override
	public void encrypt(final byte[] aBuffer, int aOffset, final int aLength, final BlockCipher aCipher, long aStartDataUnitNo, final int aUnitSize, final int[] aBlockIV, BlockCipher aTweakCipher)
	{
		assert (aUnitSize & (BYTES_PER_BLOCK - 1)) == 0;
		assert (aLength & (BYTES_PER_BLOCK - 1)) == 0;
		assert aLength >= aUnitSize;
		assert (aLength % aUnitSize) == 0;

		byte[] iv = new byte[2 * BYTES_PER_BLOCK]; // IV + plaintext
		int numUnits = aLength / aUnitSize;
		int numBlocks = aUnitSize / BYTES_PER_BLOCK;

		for (int unitIndex = 0; unitIndex < numUnits; unitIndex++)
		{
			prepareIV(aBlockIV, aStartDataUnitNo++, iv, aTweakCipher);

			for (int block = 0; block < numBlocks; block++, aOffset += BYTES_PER_BLOCK)
			{
				System.arraycopy(aBuffer, aOffset, iv, BYTES_PER_BLOCK, BYTES_PER_BLOCK);

				xor(iv, 0, BYTES_PER_BLOCK, aBuffer, aOffset);

				aCipher.engineEncryptBlock(iv, 0, aBuffer, aOffset);

				System.arraycopy(aBuffer, aOffset, iv, 0, BYTES_PER_BLOCK);

				xor(iv, 0, BYTES_PER_BLOCK, iv, BYTES_PER_BLOCK);
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

		byte[] iv = new byte[2 * BYTES_PER_BLOCK]; // IV + next IV
		int numUnits = aLength / aUnitSize;
		int numBlocks = aUnitSize / BYTES_PER_BLOCK;

		for (int unitIndex = 0; unitIndex < numUnits; unitIndex++)
		{
			prepareIV(aBlockIV, aStartDataUnitNo++, iv, aTweakCipher);

			for (int block = 0, ivOffset = 0; block < numBlocks; block++, ivOffset = BYTES_PER_BLOCK - ivOffset, aOffset += BYTES_PER_BLOCK)
			{
				System.arraycopy(aBuffer, aOffset, iv, BYTES_PER_BLOCK - ivOffset, BYTES_PER_BLOCK);

				aCipher.engineDecryptBlock(aBuffer, aOffset, aBuffer, aOffset);

				xor(aBuffer, aOffset, BYTES_PER_BLOCK, iv, ivOffset);

				xor(iv, BYTES_PER_BLOCK - ivOffset, BYTES_PER_BLOCK, aBuffer, aOffset);
			}
		}
	}
}