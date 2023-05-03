package org.terifan.raccoon.security.cryptography.ciphermode;

import java.util.Arrays;
import org.terifan.raccoon.security.cryptography.AES;
import org.terifan.raccoon.security.cryptography.BlockCipher;
import org.terifan.raccoon.security.cryptography.SecretKey;
import org.terifan.raccoon.security.cryptography.Twofish;
import org.terifan.raccoon.security.random.SecureRandom;


public class Demo
{
	public static void main(String... args)
	{
		try
		{
			int unitSize = 128;

			SecureRandom rnd = new SecureRandom();
			byte[] cipherKey = rnd.bytes(32).toArray();
			byte[] tweakKey = rnd.bytes(32).toArray();

			BlockCipher cipher = new AES(new SecretKey(cipherKey));
			BlockCipher tweakCipher = new Twofish(new SecretKey(tweakKey));

			// the entire unit is destroyed by a single bit change anywhere
//			CipherMode instance = new ElephantCipherMode();

			// one cipher block + one byte in next block is destroyed
//			CipherMode instance = new CBCCipherMode();

			// the altered cipher block and all following blocks are destroyed
//			CipherMode instance = new PCBCCipherMode();

			// one cipher block is destroyed
			CipherMode instance = new XTSCipherMode();

			// one bit is destroyed
//			CipherMode instance = new OFBCipherMode();

			int[] blockIV = rnd.ints(4).toArray();
			long unitIndex = rnd.nextLong();

			byte[] clearText = new byte[3 * unitSize];
//			byte[] clearText = rnd.bytes(3 * unitSize).toArray();

			byte[] encoded = clearText.clone();
			instance.encrypt(encoded, 0, 3 * unitSize, cipher, unitIndex, unitSize, blockIV, tweakCipher);

			// flip a single bit in the middle unit
			encoded[unitSize + rnd.nextInt(unitSize)] ^= 1 << rnd.nextInt(8);

			byte[] decoded = encoded.clone();
			instance.decrypt(decoded, 0, 3 * unitSize, cipher, unitIndex, unitSize, blockIV, tweakCipher);

			System.out.println("CLEARTEXT");
			ByteArrayUtil.hexDump(clearText);
			System.out.println("ENCODED");
			ByteArrayUtil.hexDump(encoded);
			System.out.println("DECODED");
			ByteArrayUtil.hexDump(decoded, clearText);
			System.out.println();
			System.out.println(Arrays.equals(clearText, decoded));
		}
		catch (Exception e)
		{
			e.printStackTrace(System.out);
		}
	}
}
