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

	private final char[][] Rcon = { { 0x00, 0x00, 0x00, 0x00 }, { 0x01, 0x00, 0x00, 0x00 }, { 0x02, 0x00, 0x00, 0x00 },
			{ 0x04, 0x00, 0x00, 0x00 }, { 0x08, 0x00, 0x00, 0x00 }, { 0x10, 0x00, 0x00, 0x00 },
			{ 0x20, 0x00, 0x00, 0x00 }, { 0x40, 0x00, 0x00, 0x00 }, { 0x80, 0x00, 0x00, 0x00 },
			{ 0x1b, 0x00, 0x00, 0x00 }, { 0x36, 0x00, 0x00, 0x00 } };

	public AES_Encryption(char[] sbox, byte[] key, ArrayList<byte[]> source) {
		this.key = key;
		this.source = source;
		this.sbox = sbox;
		this.w = new ArrayList<byte[]>();
		this.state = new byte[4][4];
	}

	public void encrypt() {
		int Nb = 4;
		int Nr = 14;
		
		this.keyExpansion(this.key);
		for (int i = 0; i < source.size(); i++) {
			byte[] curr = source.get(i);
			this.GenerateState(curr);
			this.addRoundKey(this.state, this.source, 0, Nb );
		}
	}

	private void GenerateState(byte[] line) {
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				state[i][j] = line[i + 4 * j];
			}
		}
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
			tmp = w.get(i - 1);
			if (i % Nk == 0) {
				tmp = this.SubWord(this.rotWord(tmp));
				for (int k = 0; k < 4; k++) {
					tmp[k] ^= (byte) this.Rcon[i / Nk][k];
				}
			} else if (Nk > 6 && i % Nk == 4) {
				tmp = this.SubWord(tmp);
			}
			byte[] result = new byte[4];
			for (int j = 0; j < 4; j++) {
				result[j] = (byte) (w.get(i - Nk)[j] ^ tmp[j]);
			}
			w.add(i, result);
		}

	}

	private byte[] SubWord(byte[] byteArray) {
		for (int i = 0; i < 4; i++) {
			// System.out.println("value is: " + (byteArray[i]&0xFF) + " Table
			// has: "+(byte)this.sbox[byteArray[i]&0xFF]);
			byteArray[i] = (byte) this.sbox[byteArray[i] & 0xFF];
		}
		return byteArray;
	}

	// shift by one
	private byte[] rotWord(byte[] byteArray) {
		byte[] tmp = new byte[4];
		for (int i = 0; i < 3; i++) {
			tmp[i] = byteArray[i + 1];
		}
		tmp[3] = byteArray[0];
		byteArray = tmp;
		return byteArray;
	}

	private void addRoundKey(byte [][] state, ArrayList<byte[]> w, int Round, int Nb) {
		for(int i = 0 ; i <Nb ; i++){
			for(int j = 0 ; j <Nb;j++){
				state[i][j] ^= w.get(Round*Nb+j)[i];
			}
		}
	}
}
