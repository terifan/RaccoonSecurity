package org.terifan.raccoon.security.cryptography.ciphermode;

import java.util.Random;
import org.terifan.raccoon.security.cryptography.AES;
import org.terifan.raccoon.security.cryptography.Serpent;
import org.terifan.raccoon.security.cryptography.Twofish;
import org.terifan.raccoon.security.cryptography.ciphermode.CBCElephantCipherMode;
import org.testng.annotations.Test;


public class CBCElephantCipherModeNGTest extends CipherModeHelper
{
	@Test
	public void testEncryption()
	{
		int[] tweakIV = new Random(1).ints(8).toArray();

		testBlockEncryption(new CBCElephantCipherMode(tweakIV), new AES(), new AES(), 16);
		testBlockEncryption(new CBCElephantCipherMode(tweakIV), new AES(), new AES(), 24);
		testBlockEncryption(new CBCElephantCipherMode(tweakIV), new AES(), new AES(), 32);
//		testBlockEncryption(new CBCElephantCipherMode(tweakIV), new Kuznechik(), new Kuznechik(), 32);
		testBlockEncryption(new CBCElephantCipherMode(tweakIV), new Twofish(), new Twofish(), 8);
		testBlockEncryption(new CBCElephantCipherMode(tweakIV), new Twofish(), new Twofish(), 16);
		testBlockEncryption(new CBCElephantCipherMode(tweakIV), new Twofish(), new Twofish(), 24);
		testBlockEncryption(new CBCElephantCipherMode(tweakIV), new Twofish(), new Twofish(), 32);
		testBlockEncryption(new CBCElephantCipherMode(tweakIV), new Serpent(), new Serpent(), 16);
		testBlockEncryption(new CBCElephantCipherMode(tweakIV), new Serpent(), new Serpent(), 24);
		testBlockEncryption(new CBCElephantCipherMode(tweakIV), new Serpent(), new Serpent(), 32);
	}
}
