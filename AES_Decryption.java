import java.math.BigInteger;
import java.util.ArrayList;

public class AES_Decryption {

	private byte[] key;
	private ArrayList<byte[]> source;
	private char[] sbox;
	private String inputFileName;

	public AES_Decryption(char[] sbox, byte[] key, ArrayList<byte[]> source, String inputFileName) {
		this.key = key;
		this.source = source;
		this.sbox = sbox;
		this.inputFileName = inputFileName;
	}

	public void decrypt() {
		// TODO Auto-generated method stub
		
	}
}
