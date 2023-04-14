package org.terifan.security.cryptography.ciphermode;

import java.util.Arrays;
import java.util.Random;
import org.terifan.security.cryptography.BlockCipher;
import org.terifan.security.cryptography.SecretKey;
import org.terifan.security.cryptography.Twofish;
import static org.terifan.security.cryptography.ciphermode.ByteArrayUtil.copyInt32;
import org.terifan.security.random.SecureRandom;


public final class CBCElephantCipherMode extends CipherMode
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

	private final transient int[] mTweak;


	public CBCElephantCipherMode(long aTweakSeed)
	{
		mTweak = new int[8];

		SecureRandom prng = new SecureRandom(aTweakSeed);
		for (int i = 0; i < 64; i++)
		{
			mTweak[i & 7] ^= prng.nextInt();
		}
	}


	public CBCElephantCipherMode(int[] aTweak)
	{
		if (aTweak.length != 8)
		{
			throw new IllegalArgumentException("The tweak IV must be " + 8 + " ints.");
		}

		mTweak = aTweak;
	}


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
			prepareTweak(mTweak, aStartDataUnitNo + unitIndex, tweak, aTweakCipher);

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
			prepareTweak(mTweak, aStartDataUnitNo + unitIndex, tweak, aTweakCipher);

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


	private void prepareTweak(int[] aSourceTweak, long aDataUnitNo, int[] aTweak, BlockCipher aTweakCipher)
	{
		aTweak[0] = aSourceTweak[0] + (int)(aDataUnitNo >>> 32);
		aTweak[1] = aSourceTweak[1] + (int)(aDataUnitNo);
		aTweak[2] = aSourceTweak[2];
		aTweak[3] = aSourceTweak[3];

		aTweak[4] = aSourceTweak[4] + (int)(aDataUnitNo >>> 32);
		aTweak[5] = aSourceTweak[5] + (int)(aDataUnitNo);
		aTweak[6] = aSourceTweak[6];
		aTweak[7] = aSourceTweak[7] + 1;

//		ByteArrayUtil.hexDump(ByteArrayUtil.toBytes(aTweak));

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
//			Random rnd = new Random(1);
////			int[] tweakIV = rnd.ints(8).toArray();
//			int[] tweakIV = new int[8];//rnd.ints(8).toArray();
//			byte[] cipherKey = new byte[32];
//			byte[] tweakKey = new byte[32];
//			rnd.nextBytes(cipherKey);
//			rnd.nextBytes(tweakKey);
//
//			BlockCipher cipher = new Twofish(new SecretKey(cipherKey));
//			BlockCipher tweakCipher = new Twofish(new SecretKey(tweakKey));
////			CipherMode instance = new CBCElephantCipherMode(tweakIV);
//			CipherMode instance = new CBCElephantCipherMode(98797);
//
//			int[] blockIV = new Random(1).ints(4).toArray();
//			long unitIndex = 0;//rnd.nextLong();
//
//			for (int test = 0; test < 3; test++)
//			{
//				byte[] clearText = new byte[3 * L];
//
//				// update a single bit in each unit, entire unit is "diffused" by the single bit
//				clearText[0 * L + rnd.nextInt(L)] = (byte)(1 << rnd.nextInt(8));
//				clearText[1 * L + rnd.nextInt(L)] = (byte)(1 << rnd.nextInt(8));
//				clearText[2 * L + rnd.nextInt(L)] = (byte)(1 << rnd.nextInt(8));
//
//				byte[] encoded = clearText.clone();
//				instance.encrypt(encoded, 0, 3 * L, cipher, unitIndex + 0, L, blockIV, tweakCipher);
//
//				byte[] decoded = encoded.clone();
//				instance.decrypt(decoded, 0, 1 * L, cipher, unitIndex + 0, L, blockIV, tweakCipher);
//				instance.decrypt(decoded, L, 2 * L, cipher, unitIndex + 1, L, blockIV, tweakCipher);
//
////				System.out.println("CLEARTEXT");
////				ByteArrayUtil.hexDump(clearText);
//				System.out.println("ENCODED");
//				ByteArrayUtil.hexDump(encoded);
////				System.out.println("DECODED");
////				ByteArrayUtil.hexDump(decoded);
//				System.out.println(Arrays.equals(clearText, decoded));
//			}
//		}
//		catch (Exception e)
//		{
//			e.printStackTrace(System.out);
//		}
//	}
}
