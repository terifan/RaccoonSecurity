package org.terifan.security.cryptography.ciphermode;

import org.terifan.security.cryptography.ciphermode.CBCElephantCipherMode;
import java.util.Random;
import org.terifan.security.cryptography.AES;
import org.terifan.security.cryptography.Serpent;
import org.terifan.security.cryptography.Twofish;
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
