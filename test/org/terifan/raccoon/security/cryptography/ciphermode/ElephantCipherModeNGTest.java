package org.terifan.raccoon.security.cryptography.ciphermode;

import org.terifan.raccoon.security.cryptography.AES;
import org.terifan.raccoon.security.cryptography.Kuznechik;
import org.terifan.raccoon.security.cryptography.Serpent;
import org.terifan.raccoon.security.cryptography.Twofish;
import org.testng.annotations.Test;


public class ElephantCipherModeNGTest extends CipherModeHelper
{
	@Test
	public void testEncryption()
	{
		testBlockEncryption(new ElephantCipherMode(), new AES(), new AES(), 16);
		testBlockEncryption(new ElephantCipherMode(), new AES(), new AES(), 24);
		testBlockEncryption(new ElephantCipherMode(), new AES(), new AES(), 32);
		testBlockEncryption(new ElephantCipherMode(), new Kuznechik(), new Kuznechik(), 32);
		testBlockEncryption(new ElephantCipherMode(), new Twofish(), new Twofish(), 8);
		testBlockEncryption(new ElephantCipherMode(), new Twofish(), new Twofish(), 16);
		testBlockEncryption(new ElephantCipherMode(), new Twofish(), new Twofish(), 24);
		testBlockEncryption(new ElephantCipherMode(), new Twofish(), new Twofish(), 32);
		testBlockEncryption(new ElephantCipherMode(), new Serpent(), new Serpent(), 16);
		testBlockEncryption(new ElephantCipherMode(), new Serpent(), new Serpent(), 24);
		testBlockEncryption(new ElephantCipherMode(), new Serpent(), new Serpent(), 32);
	}
}
