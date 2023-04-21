package org.terifan.raccoon.security.cryptography.ciphermode;

import java.util.Random;
import org.terifan.raccoon.security.cryptography.BlockCipher;
import org.terifan.raccoon.security.cryptography.SecretKey;
import static org.testng.Assert.*;


public class CipherModeHelper
{
	protected void testBlockEncryption(CipherMode aCipherMode, BlockCipher aCipher, BlockCipher aTweakCipher, int aKeyLength)
	{
		Random rnd = new Random();

		byte[] cipherKey = new byte[aKeyLength];
		rnd.nextBytes(cipherKey);

		byte[] tweakKey = new byte[aKeyLength];
		rnd.nextBytes(tweakKey);

		aCipher.engineInit(new SecretKey(cipherKey));
		aTweakCipher.engineInit(new SecretKey(tweakKey));

		int[] blockIV = rnd.ints(4).toArray();

		byte[] plain = new byte[1024 * 1024];
		rnd.nextBytes(plain);

		byte[] encrypted = plain.clone();

		aCipherMode.encrypt(encrypted, 1024 * 0, 1024 * 256, aCipher, 1024 * 0 / 4096, 4096, blockIV, aTweakCipher);
		aCipherMode.encrypt(encrypted, 1024 * 256, 1024 * 512, aCipher, 1024 * 256 / 4096, 4096, blockIV, aTweakCipher);
		aCipherMode.encrypt(encrypted, 1024 * 768, 1024 * 256, aCipher, 1024 * 768 / 4096, 4096, blockIV, aTweakCipher);

		byte[] decrypted = encrypted.clone();

		aCipherMode.decrypt(decrypted, 1024 * 0, 1024 * 128, aCipher, 1024 * 0 / 4096, 4096, blockIV, aTweakCipher);
		aCipherMode.decrypt(decrypted, 1024 * 128, 1024 * 896, aCipher, 1024 * 128 / 4096, 4096, blockIV, aTweakCipher);

		assertEquals(decrypted, plain);
	}
}
