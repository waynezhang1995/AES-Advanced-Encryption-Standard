import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

public class AES_Encryption {

	private char[] sbox;
	private byte[] key;
	private ArrayList<byte[]> source;

	public AES_Encryption(char[] sbox, byte[] key, ArrayList<byte[]> source) {
		this.key = key;
		this.source = source;
		this.sbox = sbox;
	}

	public void encrypt() {
		addRoundKey();

	}

	private void addRoundKey() {
		System.out.println(Arrays.toString(source.get(0)));
	}

}
