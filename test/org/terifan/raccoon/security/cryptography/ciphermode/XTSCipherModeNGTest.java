package org.terifan.security.cryptography.ciphermode;

import org.terifan.security.cryptography.AES;
import org.terifan.security.cryptography.Kuznechik;
import org.terifan.security.cryptography.Serpent;
import org.terifan.security.cryptography.Twofish;
import org.terifan.security.cryptography.ciphermode.XTSCipherMode;
import org.testng.annotations.Test;


public class XTSCipherModeNGTest extends CipherModeHelper
{
	@Test
	public void testEncryption()
	{
		testBlockEncryption(new XTSCipherMode(), new AES(), new AES(), 16);
		testBlockEncryption(new XTSCipherMode(), new AES(), new AES(), 24);
		testBlockEncryption(new XTSCipherMode(), new AES(), new AES(), 32);
		testBlockEncryption(new XTSCipherMode(), new Kuznechik(), new Kuznechik(), 32);
		testBlockEncryption(new XTSCipherMode(), new Twofish(), new Twofish(), 8);
		testBlockEncryption(new XTSCipherMode(), new Twofish(), new Twofish(), 16);
		testBlockEncryption(new XTSCipherMode(), new Twofish(), new Twofish(), 24);
		testBlockEncryption(new XTSCipherMode(), new Twofish(), new Twofish(), 32);
		testBlockEncryption(new XTSCipherMode(), new Serpent(), new Serpent(), 16);
		testBlockEncryption(new XTSCipherMode(), new Serpent(), new Serpent(), 24);
		testBlockEncryption(new XTSCipherMode(), new Serpent(), new Serpent(), 32);
	}
}
