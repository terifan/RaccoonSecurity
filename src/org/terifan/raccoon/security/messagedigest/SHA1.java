package org.terifan.raccoon.security.messagedigest;

import java.security.MessageDigest;


/**
 * An implementation of the SHA-1 Algorithm
 *
 * Implementation from bouncycastle.org
 *
 * Copyright (c) 2000-2006 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)
 */
public final class SHA1 extends MessageDigest implements Cloneable
{
	private static final int DIGEST_LENGTH = 20;

	private int H1, H2, H3, H4, H5;
	private int[] X = new int[80];
	private int xOff;
    private byte[]  xBuf;
    private int     xBufOff;
    private long    byteCount;


	public SHA1()
	{
		super("SHA1");

        xBuf = new byte[4];
        xBufOff = 0;

		reset();
	}

    /**
     * Constructor for cloning
     */
    public SHA1(SHA1 aBase)
    {
		super("SHA1");

		H1 = aBase.H1;
		H2 = aBase.H2;
		H3 = aBase.H3;
		H4 = aBase.H4;
		H5 = aBase.H5;
		X = aBase.X.clone();
		xOff = aBase.xOff;
	    xBuf = aBase.xBuf.clone();
	    xBufOff = aBase.xBufOff;
	    byteCount = aBase.byteCount;
    }


	@Override
    public void engineUpdate(byte in)
    {
        xBuf[xBufOff++] = in;

        if (xBufOff == xBuf.length)
        {
            processWord(xBuf, 0);
            xBufOff = 0;
        }

        byteCount++;
    }

	@Override
    public void engineUpdate(byte [] in, int inOff, int len)
    {
        //
        // fill the current word
        //
        while ((xBufOff != 0) && (len > 0))
        {
            update(in[inOff]);

            inOff++;
            len--;
        }

        //
        // process whole words.
        //
        while (len > xBuf.length)
        {
            processWord(in, inOff);

            inOff += xBuf.length;
            len -= xBuf.length;
            byteCount += xBuf.length;
        }

        //
        // load in the remainder.
        //
        while (len > 0)
        {
            update(in[inOff]);

            inOff++;
            len--;
        }
    }

	@Override
	protected int engineDigest(byte[] out, int outOff, int len)
	{
		finish();

		unpackWord(H1, out, outOff);
		unpackWord(H2, out, outOff + 4);
		unpackWord(H3, out, outOff + 8);
		unpackWord(H4, out, outOff + 12);
		unpackWord(H5, out, outOff + 16);

		reset();

		return DIGEST_LENGTH;
	}

	@Override
	protected byte [] engineDigest()
	{
		byte [] buf = new byte[DIGEST_LENGTH];

		engineDigest(buf, 0, buf.length);

		return buf;
	}

	@Override
	protected int engineGetDigestLength()
	{
		return DIGEST_LENGTH;
	}


	private void processWord(byte[] in, int inOff)
	{
		X[xOff++] = (in[inOff] & 0xff) << 24 | (in[inOff + 1] & 0xff) << 16 | (in[inOff + 2] & 0xff) << 8 | in[inOff + 3] & 0xff;

		if (xOff == 16)
		{
			processBlock();
		}
	}

	private void unpackWord(int word, byte[] out, int outOff)
	{
		out[outOff++] = (byte)(word >>> 24);
		out[outOff++] = (byte)(word >>> 16);
		out[outOff++] = (byte)(word >>> 8);
		out[outOff++] = (byte)word;
	}

	private void processLength(long bitLength)
	{
		if (xOff > 14)
		{
			processBlock();
		}

		X[14] = (int)(bitLength >>> 32);
		X[15] = (int)(bitLength & 0xffffffff);
	}

    public void finish()
    {
        long    bitLength = (byteCount << 3);

        //
        // add the pad bytes.
        //
        update((byte)128);

        while (xBufOff != 0)
        {
            update((byte)0);
        }

        processLength(bitLength);

        processBlock();
    }


	@Override
	protected void engineReset()
	{
        byteCount = 0;

        xBufOff = 0;
        for (int i = 0; i < xBuf.length; i++)
        {
            xBuf[i] = 0;
        }

		H1 = 0x67452301;
		H2 = 0xefcdab89;
		H3 = 0x98badcfe;
		H4 = 0x10325476;
		H5 = 0xc3d2e1f0;

		xOff = 0;
		for (int i = 0; i != X.length; i++)
		{
			X[i] = 0;
		}
	}


	private static final int Y1 = 0x5a827999;
	private static final int Y2 = 0x6ed9eba1;
	private static final int Y3 = 0x8f1bbcdc;
	private static final int Y4 = 0xca62c1d6;

	private int f(int u, int v, int w)
	{
		return ((u & v) | ((~u) & w));
	}

	private int h(int u, int v, int w)
	{
		return (u ^ v ^ w);
	}

	private int g(int u, int v, int w)
	{
		return ((u & v) | (u & w) | (v & w));
	}

	private void processBlock()
	{
		//
		// expand 16 word block into 80 word block.
		//
		for (int i = 16; i < 80; i++)
		{
			int t = X[i - 3] ^ X[i - 8] ^ X[i - 14] ^ X[i - 16];
			X[i] = t << 1 | t >>> 31;
		}

		//
		// set up working variables.
		//
		int	 A = H1;
		int	 B = H2;
		int	 C = H3;
		int	 D = H4;
		int	 E = H5;

		//
		// round 1
		//
		int idx = 0;

		for (int j = 0; j < 4; j++)
		{
			// E = rotateLeft(A, 5) + f(B, C, D) + E + X[idx++] + Y1
			// B = rotateLeft(B, 30)
			E += (A << 5 | A >>> 27) + f(B, C, D) + X[idx++] + Y1;
			B = B << 30 | B >>> 2;

			D += (E << 5 | E >>> 27) + f(A, B, C) + X[idx++] + Y1;
			A = A << 30 | A >>> 2;

			C += (D << 5 | D >>> 27) + f(E, A, B) + X[idx++] + Y1;
			E = E << 30 | E >>> 2;

			B += (C << 5 | C >>> 27) + f(D, E, A) + X[idx++] + Y1;
			D = D << 30 | D >>> 2;

			A += (B << 5 | B >>> 27) + f(C, D, E) + X[idx++] + Y1;
			C = C << 30 | C >>> 2;
		}

		//
		// round 2
		//
		for (int j = 0; j < 4; j++)
		{
			// E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y2
			// B = rotateLeft(B, 30)
			E += (A << 5 | A >>> 27) + h(B, C, D) + X[idx++] + Y2;
			B = B << 30 | B >>> 2;

			D += (E << 5 | E >>> 27) + h(A, B, C) + X[idx++] + Y2;
			A = A << 30 | A >>> 2;

			C += (D << 5 | D >>> 27) + h(E, A, B) + X[idx++] + Y2;
			E = E << 30 | E >>> 2;

			B += (C << 5 | C >>> 27) + h(D, E, A) + X[idx++] + Y2;
			D = D << 30 | D >>> 2;

			A += (B << 5 | B >>> 27) + h(C, D, E) + X[idx++] + Y2;
			C = C << 30 | C >>> 2;
		}

		//
		// round 3
		//
		for (int j = 0; j < 4; j++)
		{
			// E = rotateLeft(A, 5) + g(B, C, D) + E + X[idx++] + Y3
			// B = rotateLeft(B, 30)
			E += (A << 5 | A >>> 27) + g(B, C, D) + X[idx++] + Y3;
			B = B << 30 | B >>> 2;

			D += (E << 5 | E >>> 27) + g(A, B, C) + X[idx++] + Y3;
			A = A << 30 | A >>> 2;

			C += (D << 5 | D >>> 27) + g(E, A, B) + X[idx++] + Y3;
			E = E << 30 | E >>> 2;

			B += (C << 5 | C >>> 27) + g(D, E, A) + X[idx++] + Y3;
			D = D << 30 | D >>> 2;

			A += (B << 5 | B >>> 27) + g(C, D, E) + X[idx++] + Y3;
			C = C << 30 | C >>> 2;
		}

		//
		// round 4
		//
		for (int j = 0; j <= 3; j++)
		{
			// E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y4
			// B = rotateLeft(B, 30)
			E += (A << 5 | A >>> 27) + h(B, C, D) + X[idx++] + Y4;
			B = B << 30 | B >>> 2;

			D += (E << 5 | E >>> 27) + h(A, B, C) + X[idx++] + Y4;
			A = A << 30 | A >>> 2;

			C += (D << 5 | D >>> 27) + h(E, A, B) + X[idx++] + Y4;
			E = E << 30 | E >>> 2;

			B += (C << 5 | C >>> 27) + h(D, E, A) + X[idx++] + Y4;
			D = D << 30 | D >>> 2;

			A += (B << 5 | B >>> 27) + h(C, D, E) + X[idx++] + Y4;
			C = C << 30 | C >>> 2;
		}


		H1 += A;
		H2 += B;
		H3 += C;
		H4 += D;
		H5 += E;

		//
		// reset start of the buffer.
		//
		xOff = 0;
		for (int i = 0; i < 16; i++)
		{
			X[i] = 0;
		}
	}


	@Override
	public String toString()
	{
		return "SHA1";
	}


	@Override
	public SHA1 clone()
	{
		return new SHA1(this);
	}
}