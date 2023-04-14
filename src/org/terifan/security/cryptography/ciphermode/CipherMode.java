package org.terifan.security.cryptography.ciphermode;

import org.terifan.security.cryptography.BlockCipher;



public abstract class CipherMode
{
	public CipherMode()
	{
	}


	/**
	 * Encrypts a buffer using the cipher mode and the provided ciphers.
	 *
	 * @param aBuffer the buffer to encrypt
	 * @param aOffset the start offset in the buffer
	 * @param aLength number of bytes to encrypt; must be divisible by 16
	 * @param aStartDataUnitNo the sequential number of the data unit with which the buffer starts.
	 * @param aUnitSize size of a unit, the length must be a multiple of unit size
	 * @param aCipher the primary key schedule
	 * @param aBlockIV initialization vector for this block
	 * @param aTweakCipher cipher to used to encrypt the IV
	 */
	public abstract void encrypt(final byte[] aBuffer, final int aOffset, final int aLength, final BlockCipher aCipher, final long aStartDataUnitNo, final int aUnitSize, final int[] aBlockIV, BlockCipher aTweakCipher);


	/**
	 * Decrypts a buffer using the cipher mode and the provided ciphers.
	 *
	 * @param aBuffer the buffer to encrypt
	 * @param aOffset the start offset in the buffer
	 * @param aLength number of bytes to encrypt; must be divisible by 16
	 * @param aStartDataUnitNo the sequential number of the data unit with which the buffer starts.
	 * @param aUnitSize size of a unit, the length must be a multiple of unit size
	 * @param aCipher the primary key schedule
	 * @param aBlockIV initialization vector for this block
	 * @param aTweakCipher cipher to used to encrypt the IV
	 */
	public abstract void decrypt(final byte[] aBuffer, final int aOffset, final int aLength, final BlockCipher aCipher, final long aStartDataUnitNo, final int aUnitSize, final int[] aBlockIV, BlockCipher aTweakCipher);


	protected static void prepareIV(int[] aBlockIV, long aDataUnitNo, byte[] aOutputIV, BlockCipher aTweakCipher)
	{
		assert aTweakCipher != null;
		assert aBlockIV.length == 4;
		assert aOutputIV.length >= 16;

		putInt32(aOutputIV,  0, aBlockIV[0]);
		putInt32(aOutputIV,  4, aBlockIV[1]);
		putInt32(aOutputIV,  8, aBlockIV[2] ^ (int)(aDataUnitNo >>> 32));
		putInt32(aOutputIV, 12, aBlockIV[3] ^ (int)(aDataUnitNo       ));

		aTweakCipher.engineEncryptBlock(aOutputIV, 0, aOutputIV, 0);
	}


	protected static void prepareIV(int[] aBlockIV, long aDataUnitNo, int[] aOutputIV, BlockCipher aTweakCipher)
	{
		assert aTweakCipher != null;
		assert aBlockIV.length == 4;
		assert aOutputIV.length >= 4;

		aOutputIV[0] = aBlockIV[0];
		aOutputIV[1] = aBlockIV[1];
		aOutputIV[2] = aBlockIV[2] ^ (int)(aDataUnitNo >>> 32);
		aOutputIV[3] = aBlockIV[3] ^ (int)(aDataUnitNo       );

		aTweakCipher.engineEncryptBlock(aOutputIV, 0, aOutputIV, 0);
	}


	private static void putInt32(byte[] aBuffer, int aPosition, int aValue)
	{
		aBuffer[aPosition++] = (byte)(aValue >>> 24);
		aBuffer[aPosition++] = (byte)(aValue >> 16);
		aBuffer[aPosition++] = (byte)(aValue >> 8);
		aBuffer[aPosition] = (byte)(aValue);
	}
}
