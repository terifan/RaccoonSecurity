package org.terifan.raccoon.security.random;

import java.io.ByteArrayOutputStream;
import org.terifan.security.cryptography.AES;
import static org.testng.Assert.*;
import org.testng.annotations.Test;


public class SecureRandomNGTest
{
	@Test
	public void testDeterministic()
	{
		SecureRandom prng1 = new SecureRandom(0);
		SecureRandom prng2 = new SecureRandom(0);
		assertEquals(prng1.nextInt(), prng2.nextInt());
		assertEquals(prng1.nextInt(), prng2.nextInt());
		assertEquals(prng1.nextInt(), prng2.nextInt());
	}


	@Test
	public void testFullSeed()
	{
		SecureRandom prng = new SecureRandom(new AES(), new byte[16]);
		assertEquals(prng.nextInt(), 1305671840);
		assertEquals(prng.nextInt(), -582905836);
		assertEquals(prng.nextInt(), -502383143);
	}


	@Test
	public void testNumberSeed()
	{
		SecureRandom prng = new SecureRandom(0);
		assertEquals(prng.nextInt(), 1291315233);
		assertEquals(prng.nextInt(), -1294177318);
		assertEquals(prng.nextInt(), -448124876);
	}


	@Test
	public void testNumberSeedCipher()
	{
		SecureRandom prng = new SecureRandom(new AES(), 0);
		assertEquals(prng.nextInt(), 1291315233);
		assertEquals(prng.nextInt(), -1294177318);
		assertEquals(prng.nextInt(), -448124876);
	}


	@Test
	public void testBytes()
	{
		SecureRandom prng = new SecureRandom(new AES(), 0);
		byte[] a = prng.bytes(8).toArray();
		assertEquals(a.length, 8);

		prng = new SecureRandom(new AES(), 0);
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		prng.bytes(8).iterator().forEachRemaining(b::write);
		assertEquals(b.size(), 8);

		prng = new SecureRandom(new AES(), 0);
		ByteArrayOutputStream c = new ByteArrayOutputStream();
		prng.bytes(8).forEach(c::write);
		assertEquals(c.size(), 8);

		assertEquals(a, b.toByteArray());
		assertEquals(a, c.toByteArray());
	}


	@Test(enabled = false)
	public void testStreams()
	{
		SecureRandom prng = new SecureRandom(System.currentTimeMillis());
		byte[] bytes = prng.bytes(4).toArray();
		int[] ints = prng.ints(4).toArray();
		long[] longs = prng.longs(4).toArray();

		for(byte b : bytes) System.out.println(b);
		for(int b : ints) System.out.println(b);
		for(long b : longs) System.out.println(b);

		prng.bytes(4).forEach(System.out::println);
		prng.ints(4).forEach(System.out::println);
		prng.longs(4).forEach(System.out::println);
		prng.bytes(4).iterator().forEachRemaining(System.out::println);
	}


	@Test(enabled = false)
	public void testHisto()
	{
		SecureRandom prng = new SecureRandom(System.currentTimeMillis());
		int[] histo = new int[100];
		for (int i = 0; i < 100_000_000; i++)
		{
			histo[prng.nextInt(100)]++;
		}
		int min = 100000000;
		int max = -100000000;
		for (int i = 0, k = 0; i < 10;i++)
		{
			for (int j = 0; j < 10;j++)
			{
				if(histo[k]<min)min=histo[k];
				if(histo[k]>max)max=histo[k];
				System.out.printf("%8d", histo[k++]);
			}
			System.out.println();
		}
		System.out.println(min);
		System.out.println(max);
	}


	@Test
	public void testNextBytes()
	{
		SecureRandom prng = new SecureRandom(1);
		byte[] array = new byte[10];
		prng.nextBytes(array, 0, 10);

		prng = new SecureRandom(1);
		byte[] bytes = prng.bytes(10).toArray();

		assertEquals(array, bytes);
		assertEquals(array, new byte[]{108,112,-30,9,98,-7,78,106,14,93});
	}
}
