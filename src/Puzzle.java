import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;


public class Puzzle {
	public static final int LEADING_ZEROS = 23;

	static class Converter {
		private static ByteBuffer bb = ByteBuffer.allocate(Long.BYTES);

		public static byte[] longToBytes(long l) {
			bb.putLong(0, l);
			return bb.array();
		}

		public static long bytesToLong(byte[] b) {
			bb.put(b, 0, b.length);
			bb.flip();
			return bb.getLong();
		}
	}

	private static String bytesToString(byte[] a) {
		int i;
		StringBuilder sb = new StringBuilder();
		for (byte b : a) {
			sb.append(String.format("%x", (int)b & 0xff));
		}
		return sb.toString();
	}

	public static boolean valid(byte[] b, int s) {
		final byte mask[] = {
			(byte) 0x00, (byte) 0x80, (byte) 0xc0, (byte) 0xe0,
			(byte) 0xf0, (byte) 0xf8, (byte) 0xfc, (byte) 0xfe,
			(byte) 0xff
		};

		/* Check the final position */
		if ((b[s / Byte.SIZE] & mask[s % Byte.SIZE]) != 0) return false;

		/* Check the rest quickly */
		s /= Byte.SIZE;
		while ((s--) != 0) {
			if (b[s] != 0) return false;
		}
		return true;
	}

	public static long partialHashReverse(byte[] in, int s)
		throws Exception
	{
		MessageDigest md;

		byte[] hash;
		long n = -1;

		do {
			n++;
			md = MessageDigest.getInstance("SHA-256");
			md.update(in);
			hash = md.digest(Converter.longToBytes(n));
		} while (!valid(hash, s));

		return n;
	}

	public static void main(String[] args) {
		String m = "The quick brown fox jumps over the lazy dog.";

		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			System.out.println(bytesToString(md.digest(m.getBytes())));
		} catch (Exception e) {
			e.printStackTrace();
		}

		long n = -1;

		try {
			n = partialHashReverse(m.getBytes(), 16);
		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("n      : " + n +
		                 "\nTarget : " + 16 +
		                 "\nInput  : " + m);
	}
}
