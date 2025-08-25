package org.terifan.raccoon.security.messagedigest;

import java.security.MessageDigest;
import java.util.Arrays;


public final class HMAC extends MessageDigest implements Cloneable
{
	private transient MessageDigest mMessageDigest;
	private transient byte[] mInputPad;
	private transient byte[] mOutputPad;


	private HMAC(MessageDigest aMessageDigest)
	{
		super("HMAC-" + aMessageDigest.getAlgorithm());

		mMessageDigest = aMessageDigest;
	}


	public HMAC(MessageDigest aMessageDigest, byte[] aPassword)
	{
		this(aMessageDigest);

		init(aPassword, 64);
	}


	/**
	 * Generally, do not use this constructor unless you know what you are doing.
	 *
	 * @param aBlockLength Default 64, some implementations use a block length of 128 rather than 64.
	 */
	public HMAC(MessageDigest aMessageDigest, byte[] aPassword, int aBlockLength)
	{
		this(aMessageDigest);

		init(aPassword, aBlockLength);
	}


	private void init(byte[] aPassword, int aBlockLength)
	{
		mMessageDigest.reset();

		if (aPassword.length > aBlockLength)
		{
			aPassword = mMessageDigest.digest(aPassword);
		}

		mInputPad = new byte[aBlockLength];

		System.arraycopy(aPassword, 0, mInputPad, 0, aPassword.length);

		mOutputPad = mInputPad.clone();

		for (int i = 0; i < mInputPad.length; i++)
		{
			mInputPad[i] ^= 0x36;
			mOutputPad[i] ^= 0x5c;
		}

		engineReset();
	}


	public MessageDigest getMessageDigest()
	{
		return mMessageDigest;
	}


	@Override
	protected byte[] engineDigest()
	{
		byte[] tmp = mMessageDigest.digest();
		mMessageDigest.update(mOutputPad);
		byte[] out = mMessageDigest.digest(tmp);

		engineReset();

		return out;
	}


	@Override
	protected int engineGetDigestLength()
	{
		return mMessageDigest.getDigestLength();
	}


	@Override
	protected void engineReset()
	{
		mMessageDigest.reset();
		mMessageDigest.update(mInputPad);
	}


	@Override
	protected void engineUpdate(byte aBuffer)
	{
		mMessageDigest.update(aBuffer);
	}


	@Override
	protected void engineUpdate(byte[] aBuffer, int aOffset, int aLength)
	{
		mMessageDigest.update(aBuffer, aOffset, aLength);
	}


	@Override
	public HMAC clone() throws CloneNotSupportedException
	{
		HMAC h = new HMAC((MessageDigest)mMessageDigest.clone());
		h.mInputPad = mInputPad.clone();
		h.mOutputPad = mOutputPad.clone();
		return h;
	}


	@Override
	public String toString()
	{
		return "HMAC-" + mMessageDigest.toString();
	}


	@Override
	public void reset()
	{
		mMessageDigest.reset();
		Arrays.fill(mInputPad, (byte)0);
		Arrays.fill(mOutputPad, (byte)0);
		super.reset();
	}
}
