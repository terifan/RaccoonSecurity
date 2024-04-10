package test_security;

import java.security.MessageDigest;
import java.util.Random;
import org.terifan.raccoon.security.messagedigest.Fletcher4;
import org.terifan.raccoon.security.messagedigest.MurmurHash3;
import org.terifan.raccoon.security.messagedigest.SHA3;
import org.terifan.raccoon.security.messagedigest.SHA512;
import org.terifan.raccoon.security.messagedigest.Skein512;


public class ChecksumPerformance
{
	public static void main(String... args)
	{
		try
		{
			byte[] data = new byte[1000 * 1024 * 1024];
			new Random(1).nextBytes(data);

			long[] t = new long[20];

			for (int i = 0; i < 1000; i++)
			{
				t[0] -= System.currentTimeMillis();
				Fletcher4.hash128(data, 0, data.length, 0xcafebabe);
				t[0] += System.currentTimeMillis();

				t[1] -= System.currentTimeMillis();
				SHA3.hash128_256(data, 0, data.length, 0xcafebabe);
				t[1] += System.currentTimeMillis();

				t[2] -= System.currentTimeMillis();
				SHA3.hash128_512(data, 0, data.length, 0xcafebabe);
				t[2] += System.currentTimeMillis();

				t[3] -= System.currentTimeMillis();
				SHA512.hash128(data, 0, data.length, 0xcafebabe);
				t[3] += System.currentTimeMillis();

				t[4] -= System.currentTimeMillis();
				Skein512.hash128(data, 0, data.length, 0xcafebabe);
				t[4] += System.currentTimeMillis();

				t[5] -= System.currentTimeMillis();
				MurmurHash3.hash128(data, 0, data.length, 0xcafebabe);
				t[5] += System.currentTimeMillis();

				t[6] -= System.currentTimeMillis();
				MessageDigest.getInstance("SHA-256").digest(data, 0, data.length);
				t[6] += System.currentTimeMillis();

				t[7] -= System.currentTimeMillis();
				MessageDigest.getInstance("SHA-512").digest(data, 0, data.length);
				t[7] += System.currentTimeMillis();

				t[8] -= System.currentTimeMillis();
				MessageDigest.getInstance("MD5").digest(data, 0, data.length);
				t[8] += System.currentTimeMillis();

				System.out.printf("%7d %7d %7d %7d %7d %7d %7d %7d %7d %n", t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8]);
			}
		}
		catch (Throwable e)
		{
			e.printStackTrace(System.out);
		}
	}
}
