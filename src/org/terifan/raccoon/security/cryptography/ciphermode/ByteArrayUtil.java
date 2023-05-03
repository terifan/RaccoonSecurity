package org.terifan.raccoon.security.cryptography.ciphermode;


final class ByteArrayUtil
{
	static void xor(byte[] aDstBuffer, int aDstOffset, int aLength, byte[] aXorBuffer, int aXorOffset)
	{
		for (int i = 0; i < aLength; i++)
		{
			aDstBuffer[aDstOffset++] ^= aXorBuffer[aXorOffset++];
		}
	}


	static void hexDump(byte[] aBuffer)
	{
		hexDump(aBuffer, null);
	}


	static void hexDump(byte[] aBuffer, byte[] aCompareWith)
	{
		int MR = aBuffer.length;
		int LW = 32;

		StringBuilder binText = new StringBuilder("");
		StringBuilder hexText = new StringBuilder("");

		for (int row = 0, offset = 0; offset < aBuffer.length && row < MR; row++)
		{
			hexText.append("\033[1;30m" + String.format("%04d: ", row * LW) + "\033[0m");

			int padding = 3 * LW + LW / 8;
			String mode = "";

			for (int i = 0; offset < aBuffer.length && i < LW; i++, offset++)
			{
				int c = 0xff & aBuffer[offset];

				String nextMode;
				if (aCompareWith != null && c != (0xff & aCompareWith[offset]))
				{
					nextMode = "\033[1;31m";
				}
				else if (c >= '0' && c <= '9')
				{
					nextMode = "\033[0;35m";
				}
				else if (!(c < ' ' || c >= 128))
				{
					nextMode = "\033[0;36m";
				}
				else
				{
					nextMode = "\033[0m";
				}
				if (!nextMode.equals(mode))
				{
					mode = nextMode;
					hexText.append(mode);
					binText.append(mode);
				}

				hexText.append(String.format("%02x ", c));
				binText.append(Character.isISOControl(c) ? '.' : (char)c);

				padding -= 3;

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

			System.out.println(hexText + "\033[0m" + binText + "\033[0m");

			binText.setLength(0);
			hexText.setLength(0);
		}
	}
}
