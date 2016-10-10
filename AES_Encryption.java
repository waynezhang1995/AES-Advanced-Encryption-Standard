import java.math.BigInteger;

public class AES_Encryption {

	private char[] sbox;
	private byte[] key;
	private byte[] source;

	public AES_Encryption(char[] sbox, byte[] key, byte[][] context) {
		this.key = key;
		this.source = source;
		this.sbox = sbox;
	}
}
