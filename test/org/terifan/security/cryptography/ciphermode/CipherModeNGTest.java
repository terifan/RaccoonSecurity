package org.terifan.security.cryptography.ciphermode;

import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.Random;
import org.terifan.security.cryptography.AES;
import org.terifan.security.cryptography.BlockCipher;
import org.terifan.security.cryptography.SecretKey;
import static org.testng.Assert.*;
import org.testng.annotations.Test;


public class CipherModeNGTest
{
	@Test
	public void testPrepareIVInt()
	{
		int[] blockIV = new Random(1).ints(4).toArray();
		long dataUnitNo = 51515;
		int[] outputIVInts = new int[4];
		BlockCipher tweakCipher = new AES(new SecretKey(HexFormat.of().parseHex("db63714ee367eab51e46dd531a54d333")));

		CipherMode.prepareIV(blockIV, dataUnitNo, outputIVInts, tweakCipher);

		ByteBuffer bb = ByteBuffer.allocate(16).putInt(outputIVInts[0]).putInt(outputIVInts[1]).putInt(outputIVInts[2]).putInt(outputIVInts[3]);

		assertEquals(HexFormat.of().formatHex(bb.array()), "c8c57781fab88fc644812ef9023b6731");
	}


	@Test
	public void testPrepareIVByte()
	{
		int[] blockIV = new Random(1).ints(4).toArray();
		long dataUnitNo = 51515;
		byte[] outputIVBytes = new byte[16];
		BlockCipher tweakCipher = new AES(new SecretKey(HexFormat.of().parseHex("db63714ee367eab51e46dd531a54d333")));

		CipherMode.prepareIV(blockIV, dataUnitNo, outputIVBytes, tweakCipher);

		assertEquals(HexFormat.of().formatHex(outputIVBytes), "c8c57781fab88fc644812ef9023b6731");
	}
}
