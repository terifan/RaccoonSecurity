package org.terifan.raccoon.security.cryptography.ciphermode;

import org.terifan.raccoon.security.cryptography.BlockCipher;


public final class ElephantCipherMode extends CipherMode
{
	private final static int BYTES_PER_CIPHER_BLOCK = 16;

	private final static int[] ROTATE1 =
	{
		9, 0, 13, 0
	};
	private final static int[] ROTATE2 =
	{
		0, 10, 0, 25
	};


	@Override
	public void encrypt(final byte[] aBuffer, int aOffset, final int aLength, final BlockCipher aCipher, long aStartDataUnitNo, final int aUnitSize, final int[] aBlockIV, BlockCipher aTweakCipher)
	{
		int[] ra = ROTATE1;
		int[] rb = ROTATE2;
		int[] iv = new int[4];
		int[] tweak = new int[8];
		int[] words = new int[aLength / 4];
		int wordsPerUnit = aUnitSize / 4;
		int wordMask = wordsPerUnit - 1;
		int blocksPerUnit = aUnitSize / BYTES_PER_CIPHER_BLOCK;
		int wordsPerCipherBlock = BYTES_PER_CIPHER_BLOCK / 4;

		for (int unitIndex = 0, offset = aOffset, numDataUnits = aLength / aUnitSize; unitIndex < numDataUnits; unitIndex++, offset += aUnitSize)
		{
			bytesToInts(aBuffer, offset, words, 0, wordsPerUnit);

			// encryption cbc mode
			prepareIV(aBlockIV, aStartDataUnitNo + unitIndex, iv, aTweakCipher);

			for (int i = 0; i < wordsPerUnit; i += wordsPerCipherBlock)
			{
				for (int j = 0; j < wordsPerCipherBlock; j++)
				{
					iv[j] ^= words[i + j];
				}

				aCipher.engineEncryptBlock(iv, 0, iv, 0);

				System.arraycopy(iv, 0, words, i, wordsPerCipherBlock);
			}

			// elephant diffuser
			prepareTweak(aBlockIV, aStartDataUnitNo + unitIndex, tweak, aTweakCipher);

			for (int i = 0; i < blocksPerUnit; i++)
			{
				words[i] ^= tweak[i & 7] ^ i;
			}

			for (int i = 5 * wordsPerUnit; --i >= 0;)
			{
				words[i & wordMask] -= (words[(i + 2) & wordMask] ^ rol(words[(i + 5) & wordMask], rb[i & 3]));
			}

			for (int i = 3 * wordsPerUnit; --i >= 0;)
			{
				words[i & wordMask] -= (words[(i - 2) & wordMask] ^ rol(words[(i - 5) & wordMask], ra[i & 3]));
			}

			intsToBytes(words, 0, aBuffer, offset, wordsPerUnit);
		}
	}


	@Override
	public void decrypt(final byte[] aBuffer, int aOffset, final int aLength, final BlockCipher aCipher, long aStartDataUnitNo, final int aUnitSize, final int[] aBlockIV, BlockCipher aTweakCipher)
	{
		if (aLength <= 0 || (aLength % aUnitSize) != 0)
		{
			throw new IllegalArgumentException("Length must be a multiple of the unit size " + aUnitSize + ".");
		}

		int[] ra = ROTATE1;
		int[] rb = ROTATE2;
		int[] iv = new int[BYTES_PER_CIPHER_BLOCK / 4];
		int[] tweak = new int[8];
		int[] temp = new int[BYTES_PER_CIPHER_BLOCK / 4];
		int[] words = new int[aLength / 4];
		int wordsPerUnit = aUnitSize / 4;
		int wordMask = wordsPerUnit - 1;
		int blocksPerUnit = aUnitSize / BYTES_PER_CIPHER_BLOCK;
		int wordsPerCipherBlock = BYTES_PER_CIPHER_BLOCK / 4;

		for (int unitIndex = 0, offset = aOffset, numDataUnits = aLength / aUnitSize; unitIndex < numDataUnits; unitIndex++, offset += aUnitSize)
		{
			bytesToInts(aBuffer, offset, words, 0, wordsPerUnit);

			// elephant diffuser
			prepareTweak(aBlockIV, aStartDataUnitNo + unitIndex, tweak, aTweakCipher);

			for (int i = 0; i < 3 * wordsPerUnit; i++)
			{
				words[i & wordMask] += (words[(i - 2) & wordMask] ^ rol(words[(i - 5) & wordMask], ra[i & 3]));
			}

			for (int i = 0; i < 5 * wordsPerUnit; i++)
			{
				words[i & wordMask] += (words[(i + 2) & wordMask] ^ rol(words[(i + 5) & wordMask], rb[i & 3]));
			}

			for (int i = 0; i < blocksPerUnit; i++)
			{
				words[i] ^= tweak[i & 7] ^ i;
			}

			// decryption cbc mode
			prepareIV(aBlockIV, aStartDataUnitNo + unitIndex, iv, aTweakCipher);

			for (int i = 0; i < wordsPerUnit; i += wordsPerCipherBlock)
			{
				System.arraycopy(words, i, temp, 0, wordsPerCipherBlock);

				aCipher.engineDecryptBlock(words, i, words, i);

				for (int j = 0; j < wordsPerCipherBlock; j++)
				{
					words[i + j] ^= iv[j];
				}

				System.arraycopy(temp, 0, iv, 0, wordsPerCipherBlock);
			}

			intsToBytes(words, 0, aBuffer, offset, wordsPerUnit);
		}
	}


	private static void prepareTweak(int[] aBlockIV, long aDataUnitNo, int[] aTweak, BlockCipher aTweakCipher)
	{
		aTweak[0] = aBlockIV[0] ^ 0xcafebabe;
		aTweak[1] = aBlockIV[1];
		aTweak[2] = aBlockIV[2] ^ (int)(aDataUnitNo >>> 32);
		aTweak[3] = aBlockIV[3] ^ (int)(aDataUnitNo);

		aTweakCipher.engineEncryptBlock(aTweak, 0, aTweak, 0);

		aTweak[4] = aTweak[0] ^ 0xdeadface;
		aTweak[5] = aTweak[1];
		aTweak[6] = aTweak[2] ^ (int)(aDataUnitNo >>> 32);
		aTweak[7] = aTweak[3] ^ (int)(aDataUnitNo);

		aTweakCipher.engineEncryptBlock(aTweak, 4, aTweak, 4);
	}


	private static int rol(int i, int distance)
	{
		return (i << distance) | (i >>> -distance);
	}


	private static void bytesToInts(byte[] aIn, int aInOffset, int[] aOut, int aOutOffset, int aNumInts)
	{
		for (int i = 0; i < aNumInts; i++)
		{
			aOut[aOutOffset++]
				= ((aIn[aInOffset++] & 0xFF) << 24)
				+ ((aIn[aInOffset++] & 0xFF) << 16)
				+ ((aIn[aInOffset++] & 0xFF) << 8)
				+ ((aIn[aInOffset++] & 0xFF));
		}
	}


	private static void intsToBytes(int[] aIn, int aInOffset, byte[] aOut, int aOutOffset, int aNumInts)
	{
		for (int i = 0; i < aNumInts; i++)
		{
			int v = aIn[aInOffset++];
			aOut[aOutOffset++] = (byte)(v >>> 24);
			aOut[aOutOffset++] = (byte)(v >> 16);
			aOut[aOutOffset++] = (byte)(v >> 8);
			aOut[aOutOffset++] = (byte)(v);
		}
	}
}
