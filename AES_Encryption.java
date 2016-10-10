import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

public class AES_Encryption {

	private char[] sbox;
	private byte[] key;
	private byte[][] state;
	private ArrayList<byte[]> w;
	private ArrayList<byte[]> source;

	public AES_Encryption(char[] sbox, byte[] key, ArrayList<byte[]> source) {
		this.key = key;
		this.source = source;
		this.sbox = sbox;
		this.w = new ArrayList<byte[]>();
		this.state = new byte[4][4];
	}

	public void encrypt() {
		//this.keyExpansion(this.key);
		addRoundKey();

	}

	private void keyExpansion(byte[] key) {
		int Nb = 4;
		int Nk = 8; // key length (in words)
		int Nr = 14; // 14 round
		// initialization
		for (int i = 0; i < Nk; i++) {
			byte[] tmp = { this.key[4 * i], this.key[4 * i + 1], this.key[4 * i + 2], this.key[4 * i + 3] };
			w.add(i, tmp);
		}

		int totalWords = Nb * (Nr + 1);
		// remaining words. we start from Nk
		for (int i = Nk; i < totalWords; i++) {
			byte[] tmp = new byte[Nb];
			w.add(i, new byte[4]);
			// for(int j = 0 ;j<Nb;j++){
			tmp = w.get(i - 1);
			// }
			if (i % Nk == 0) {
				tmp = this.SubWord(this.rotWord(tmp));
			}
		}

	}

	private byte[] SubWord(byte [] byteArray) {
		for(int i =0;i<4;i++){
			//byteArray[i] = 
		}
		return null;
	}

	private byte[] rotWord(byte[] byteArray) {
		return null;
	}

	private void addRoundKey() {
	}

}
