package org.terifan.security.cryptography.ciphermode;

import org.terifan.security.cryptography.AES;
import org.terifan.security.cryptography.Kuznechik;
import org.terifan.security.cryptography.Serpent;
import org.terifan.security.cryptography.Twofish;
import org.terifan.security.cryptography.ciphermode.CBCCipherMode;
import org.testng.annotations.Test;


public class CBCCipherModeNGTest extends CipherModeHelper
{
	@Test
	public void testEncryption()
	{
		testBlockEncryption(new CBCCipherMode(), new AES(), new AES(), 16);
		testBlockEncryption(new CBCCipherMode(), new AES(), new AES(), 24);
		testBlockEncryption(new CBCCipherMode(), new AES(), new AES(), 32);
		testBlockEncryption(new CBCCipherMode(), new Kuznechik(), new Kuznechik(), 32);
		testBlockEncryption(new CBCCipherMode(), new Twofish(), new Twofish(), 8);
		testBlockEncryption(new CBCCipherMode(), new Twofish(), new Twofish(), 16);
		testBlockEncryption(new CBCCipherMode(), new Twofish(), new Twofish(), 24);
		testBlockEncryption(new CBCCipherMode(), new Twofish(), new Twofish(), 32);
		testBlockEncryption(new CBCCipherMode(), new Serpent(), new Serpent(), 16);
		testBlockEncryption(new CBCCipherMode(), new Serpent(), new Serpent(), 24);
		testBlockEncryption(new CBCCipherMode(), new Serpent(), new Serpent(), 32);
	}
}