package org.terifan.raccoon.security.random;

import java.util.Arrays;
import java.util.Spliterators;
import java.util.function.Consumer;
import java.util.function.IntConsumer;
import java.util.function.LongConsumer;
import java.util.stream.IntStream;
import java.util.stream.LongStream;
import java.util.stream.StreamSupport;
import org.terifan.raccoon.security.cryptography.AES;
import org.terifan.raccoon.security.cryptography.BlockCipher;
import org.terifan.raccoon.security.cryptography.SecretKey;
import org.terifan.raccoon.security.messagedigest.SHA3;


/**
 * A deterministic cryptographically secure pseudorandom number generator based on block cipher in CTR mode.
 * The internal counter is 128-bits and is safe to produce 1e38 numbers.
 */
public final class SecureRandom
{
	private final transient int[] mCounter = new int[4];
	private final transient int[] mTemp = new int[4];
	private final transient BlockCipher mCipher;


	/**
	 * Creates a new random number generator using an AES cipher and current nano-time as seed.
	 */
	public SecureRandom()
	{
        this(System.nanoTime());
	}


	/**
	 * Creates a new random number generator using an AES cipher.
	 */
	public SecureRandom(long aSeed)
	{
		this(new AES(), aSeed);
	}


	/**
	 * Creates a new random number generator.
	 */
	public SecureRandom(BlockCipher aCipher, long aSeed)
	{
		this(aCipher, expandSeed(aSeed));
	}


	/**
	 * Creates a new random number generator using the provided cipher and seed. If the cipher provided isn't initialized
	 * a key is produced by hashing the seed and providing it as key.
	 *
	 * @param aCipher BlockCipher used to produce random values.
	 * @param aSeed the initial state of the counter. Must be 16 bytes.
	 */
	public SecureRandom(BlockCipher aCipher, byte[] aSeed)
	{
		if (aSeed == null || aSeed.length != 16)
		{
			throw new IllegalArgumentException("Seed must be a 16 byte array");
		}

		aSeed = aSeed.clone();

		mCipher = aCipher;

		if (!mCipher.isInitialized())
		{
			mCipher.engineInit(new SecretKey(new SHA3(256).digest(aSeed)));
		}

		mCipher.engineDecryptBlock(aSeed, 0, aSeed, 0);

		mCounter[0] = readInt32(aSeed, 0);
		mCounter[1] = readInt32(aSeed, 4);
		mCounter[2] = readInt32(aSeed, 8);
		mCounter[3] = readInt32(aSeed, 12);
	}


	public int nextInt()
	{
		mCipher.engineDecryptBlock(mCounter, 0, mTemp, 0);

		int hi = mTemp[0] ^ mTemp[1];
		int lo = mTemp[2] ^ mTemp[3];
		int v = hi ^ lo;

		mCounter[lo & 3]++;

		return v;
	}


	public long nextLong()
	{
		mCipher.engineDecryptBlock(mCounter, 0, mTemp, 0);

		int hi = mTemp[0] ^ mTemp[1];
		int lo = mTemp[2] ^ mTemp[3];
		long v = ((long)hi << 32) ^ lo;

		mCounter[lo & 3]++;

		return v;
	}


	public int nextInt(int aBound)
	{
		return Math.abs(nextInt() % aBound);
	}


	public ByteStream bytes(int aLength)
	{
		return new BytePipeline()
		{
			int remaining = aLength;
			int buffer;
			int length;


			@Override
			public boolean tryAdvance(Consumer<Byte> aConsumer)
			{
				if (remaining > 0)
				{
					if (length == 0)
					{
						buffer = nextInt();
						length = 32;
					}
					length -= 8;
					aConsumer.accept((byte)(buffer >>> length));
					return --remaining >= 0;
				}
				return false;
			}


			@Override
			public long estimateSize()
			{
				return remaining;
			}
		};
	}


	public IntStream ints(int aLength)
	{
		return StreamSupport.intStream(new Spliterators.AbstractIntSpliterator(0, 0)
		{
			int remaining = aLength;


			@Override
			public boolean tryAdvance(IntConsumer aConsumer)
			{
				aConsumer.accept(nextInt());
				return --remaining > 0;
			}
		}, false);
	}


	public LongStream longs(int aLength)
	{
		return StreamSupport.longStream(new Spliterators.AbstractLongSpliterator(0, 0)
		{
			int remaining = aLength;


			@Override
			public boolean tryAdvance(LongConsumer aConsumer)
			{
				aConsumer.accept(nextLong());
				return --remaining > 0;
			}
		}, false);
	}


	public void reset()
	{
		mCipher.engineReset();
		Arrays.fill(mCounter, 0);
		Arrays.fill(mTemp, 0);
	}


	private int readInt32(byte[] aBuffer, int aOffset)
	{
		int ch1 = 0xff & aBuffer[aOffset++];
		int ch2 = 0xff & aBuffer[aOffset++];
		int ch3 = 0xff & aBuffer[aOffset++];
		int ch4 = 0xff & aBuffer[aOffset];
		return (ch1 << 24) + (ch2 << 16) + (ch3 << 8) + ch4;
	}


	/**
	 * Fills the high eight bytes with some random values. Constants based on values found in java.lang.Random.
	 */
	private static byte[] expandSeed(long aSeed)
	{
		byte[] output = new byte[16];

		long seed = aSeed ^ 8682522807148012L;
		for (int i = 0; i < 8; i++, aSeed >>= 8)
		{
			output[i] ^= (seed = (0x5DEECE66DL * seed + 0xBL) & ((1L << 48) - 1));
			output[i + 8] ^= aSeed;
		}

		return output;
	}


	public void nextBytes(byte[] aArray)
	{
		nextBytes(aArray, 0, aArray.length);
	}


	public void nextBytes(byte[] aArray, int aOffset, int aLength)
	{
		int buffer = 0;
		int length = 0;
		for (int i = 0; i < aLength; i++)
		{
			if (length == 0)
			{
				buffer = nextInt();
				length = 32;
			}
			length -= 8;
			aArray[aOffset++] = (byte)(buffer >>> length);
		}
	}
}
