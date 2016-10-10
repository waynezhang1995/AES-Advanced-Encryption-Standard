import java.math.BigInteger;

public class AES_Decryption {

	private byte[] key;
	private byte[][] source;
	private char[] sbox;

	public AES_Decryption(char[] sbox, byte[] key, byte[][] source) {
		this.key = key;
		this.source = source;
		this.sbox = sbox;
	}
}
