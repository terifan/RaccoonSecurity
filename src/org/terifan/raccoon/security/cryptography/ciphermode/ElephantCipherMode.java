package org.terifan.raccoon.security.cryptography.ciphermode;

import java.util.Arrays;
import java.util.Random;
import org.terifan.raccoon.security.cryptography.BlockCipher;
import org.terifan.raccoon.security.cryptography.SecretKey;
import org.terifan.raccoon.security.cryptography.Twofish;
import static org.terifan.raccoon.security.cryptography.ciphermode.ByteArrayUtil.copyInt32;


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
			copyInt32(aBuffer, offset, words, 0, wordsPerUnit);

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

			copyInt32(words, 0, aBuffer, offset, wordsPerUnit);
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
			copyInt32(aBuffer, offset, words, 0, wordsPerUnit);

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

			copyInt32(words, 0, aBuffer, offset, wordsPerUnit);
		}
	}


	private void prepareTweak(int[] aBlockIV, long aDataUnitNo, int[] aTweak, BlockCipher aTweakCipher)
	{
		aDataUnitNo = -aDataUnitNo;

		aTweak[0] = aBlockIV[0] ^ 0xcafebabe;
		aTweak[1] = aBlockIV[1];
		aTweak[2] = aBlockIV[2] + (int)(aDataUnitNo >>> 32);
		aTweak[3] = aBlockIV[3] + (int)(aDataUnitNo);

		aTweak[4] = aBlockIV[0] ^ 0xdeadface;
		aTweak[5] = aBlockIV[1];
		aTweak[6] = aBlockIV[2] + (int)(aDataUnitNo >>> 32);
		aTweak[7] = aBlockIV[3] + (int)(aDataUnitNo);

		aTweakCipher.engineEncryptBlock(aTweak, 0, aTweak, 0);
		aTweakCipher.engineEncryptBlock(aTweak, 4, aTweak, 4);
	}


	private int rol(int i, int distance)
	{
		return (i << distance) | (i >>> -distance);
	}


//	public static void main(String... args)
//	{
//		try
//		{
//			int L = 32;
//
//			Random rnd = new Random();
//			byte[] cipherKey = new byte[32];
//			byte[] tweakKey = new byte[32];
//			rnd.nextBytes(cipherKey);
//			rnd.nextBytes(tweakKey);
//
//			BlockCipher cipher = new Twofish(new SecretKey(cipherKey));
//			BlockCipher tweakCipher = new Twofish(new SecretKey(tweakKey));
//			CipherMode instance = new ElephantCipherMode();
////			CipherMode instance = new CBCCipherMode();
//
//			int[] blockIV = rnd.ints(4).toArray();
//			long unitIndex = rnd.nextLong();
//
//			byte[] clearText = new byte[3 * L];
//
//			// update a single bit in each unit, entire unit is "diffused" by the single bit
//			clearText[0 * L + rnd.nextInt(L)] = (byte)(1 << rnd.nextInt(8));
//			clearText[1 * L + rnd.nextInt(L)] = (byte)(1 << rnd.nextInt(8));
//			clearText[2 * L + rnd.nextInt(L)] = (byte)(1 << rnd.nextInt(8));
//
//			byte[] encoded = clearText.clone();
//			instance.encrypt(encoded, 0, 3 * L, cipher, unitIndex + 0, L, blockIV, tweakCipher);
//
//			byte[] decoded = encoded.clone();
//			instance.decrypt(decoded, 0, 1 * L, cipher, unitIndex + 0, L, blockIV, tweakCipher);
//			instance.decrypt(decoded, L, 2 * L, cipher, unitIndex + 1, L, blockIV, tweakCipher);
//
//			System.out.println("CLEARTEXT");
//			ByteArrayUtil.hexDump(clearText);
//			System.out.println("ENCODED");
//			ByteArrayUtil.hexDump(encoded);
//			System.out.println("DECODED");
//			ByteArrayUtil.hexDump(decoded);
//			System.out.println(Arrays.equals(clearText, decoded));
//		}
//		catch (Exception e)
//		{
//			e.printStackTrace(System.out);
//		}
//	}


	public static void main(String... args)
	{
		try
		{
			int L = 128;

			Random rnd = new Random();
			byte[] cipherKey = new byte[32];
			byte[] tweakKey = new byte[32];
			rnd.nextBytes(cipherKey);
			rnd.nextBytes(tweakKey);

			BlockCipher cipher = new Twofish(new SecretKey(cipherKey));
			BlockCipher tweakCipher = new Twofish(new SecretKey(tweakKey));

			// the entire unit is destroyed by a single bit change anywhere
//			CipherMode instance = new ElephantCipherMode();

			// one cipher block + one byte in next block is destroyed
//			CipherMode instance = new CBCCipherMode();

			// the altered cipher block and all following blocks are destroyed
			CipherMode instance = new PCBCCipherMode();

			// one cipher block is destroyed
//			CipherMode instance = new XTSCipherMode();

			int[] blockIV = rnd.ints(4).toArray();
			long unitIndex = rnd.nextLong();

			byte[] clearText = new byte[3 * L];

			byte[] encoded = clearText.clone();
			instance.encrypt(encoded, 0, 3 * L, cipher, unitIndex + 0, L, blockIV, tweakCipher);

			// update a single bit in each unit, entire unit is "diffused" by the single bit
			encoded[L + rnd.nextInt(L)] = (byte)(1 << rnd.nextInt(8));

			byte[] decoded = encoded.clone();
			instance.decrypt(decoded, 0, 3 * L, cipher, unitIndex + 0, L, blockIV, tweakCipher);

			System.out.println("CLEARTEXT");
			ByteArrayUtil.hexDump(clearText);
			System.out.println("ENCODED");
			ByteArrayUtil.hexDump(encoded);
			System.out.println("DECODED");
			ByteArrayUtil.hexDump(decoded);
			System.out.println(Arrays.equals(clearText, decoded));
		}
		catch (Exception e)
		{
			e.printStackTrace(System.out);
		}
	}
}
