package org.terifan.security.cryptography.ciphermode;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;


final class ByteArrayUtil
{
	static void xor(byte[] aBuffer, int aOffset, int aLength, byte[] aMask, int aMaskOffset)
	{
		for (int i = 0; i < aLength; i++)
		{
			aBuffer[aOffset + i] ^= aMask[aMaskOffset + i];
		}
	}


	static int getInt32(byte[] aBuffer, int aPosition)
	{
		return ((aBuffer[aPosition] & 0xFF) << 24)
			+ ((aBuffer[aPosition + 1] & 0xFF) << 16)
			+ ((aBuffer[aPosition + 2] & 0xFF) << 8)
			+ ((aBuffer[aPosition + 3] & 0xFF));
	}


	static void putInt32(byte[] aBuffer, int aPosition, int aValue)
	{
		aBuffer[aPosition++] = (byte)(aValue >>> 24);
		aBuffer[aPosition++] = (byte)(aValue >> 16);
		aBuffer[aPosition++] = (byte)(aValue >> 8);
		aBuffer[aPosition] = (byte)(aValue);
	}


	static void copyInt32(byte[] aIn, int aInOffset, int[] aOut, int aOutOffset, int aNumInts)
	{
		for (int i = 0; i < aNumInts; i++, aInOffset+=4)
		{
			aOut[aOutOffset++] = getInt32(aIn, aInOffset);
		}
	}


	static void copyInt32(int[] aIn, int aInOffset, byte[] aOut, int aOutOffset, int aNumInts)
	{
		for (int i = 0; i < aNumInts; i++, aOutOffset+=4, aInOffset++)
		{
			putInt32(aOut, aOutOffset, aIn[aInOffset]);
		}
	}


	static void hexDump(byte[] aData)
	{
		int width = 32;
		int length = aData.length;
		InputStream in = new ByteArrayInputStream(aData);

		try
		{
			StringBuilder binText = new StringBuilder("");
			StringBuilder hexText = new StringBuilder("");

			for (int row = 0; row == 0 || length > 0; row++)
			{
				hexText.append(String.format("%04d: ", row * width));

				int padding = 3 * width + width / 8;

				for (int i = 0; i < width && length > 0; i++)
				{
					int c = in.read();

					if (c == -1)
					{
						length = 0;
						break;
					}

					hexText.append(String.format("%02x ", c));
					binText.append(Character.isISOControl(c) ? '.' : (char)c);
					padding -= 3;
					length--;

					if ((i & 7) == 7)
					{
						hexText.append(" ");
						padding--;
					}
				}

				for (int i = 0; i < padding; i++)
				{
					hexText.append(" ");
				}

				System.out.println(hexText.append(binText).toString());

				binText.setLength(0);
				hexText.setLength(0);
			}
		}
		catch (IOException e)
		{
			throw new IllegalStateException(e);
		}
	}
}
