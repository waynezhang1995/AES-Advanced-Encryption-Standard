import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.ArrayList;

public class AES_Decryption {

	private final char[] hexTable;
	private char[] sbox;
	private byte[] key;
	private byte[][] state;
	private byte[][] w;
	private String InputFileName;
	private ArrayList<byte[]> source;
	private ArrayList<String> outputBuffer;

	private final char[][] Rcon = { { 0x00, 0x00, 0x00, 0x00 }, { 0x01, 0x00, 0x00, 0x00 }, { 0x02, 0x00, 0x00, 0x00 },
			{ 0x04, 0x00, 0x00, 0x00 }, { 0x08, 0x00, 0x00, 0x00 }, { 0x10, 0x00, 0x00, 0x00 },
			{ 0x20, 0x00, 0x00, 0x00 }, { 0x40, 0x00, 0x00, 0x00 }, { 0x80, 0x00, 0x00, 0x00 },
			{ 0x1b, 0x00, 0x00, 0x00 }, { 0x36, 0x00, 0x00, 0x00 } };

	public AES_Decryption(char[] sbox, byte[] key, ArrayList<byte[]> source, String inputFileName) {
		this.InputFileName = inputFileName;
		this.hexTable = "0123456789ABCDEF".toCharArray();
		this.key = key;
		this.source = source;
		this.sbox = sbox;
		this.state = new byte[4][4];
		this.outputBuffer = new ArrayList<String>();
	}

	public void decrypt() {
		int Nb = 4;
		int Nr = 14;

		this.keyExpansion(this.key);
		for (int i = 0; i < this.source.size(); i++) {
			byte[] curr = this.source.get(i);
			this.GenerateState(curr);
			this.addRoundKey(this.state, this.w, Nr, Nb);

			for (int j = Nr - 1; j > 0; j--) {
				this.InverseSubBytes(Nb);
				this.InverseShiftRows(Nb);
				this.addRoundKey(this.state, this.w, j, Nb);
				this.InverseMixColumns(Nb);
			}
			this.InverseSubBytes(Nb);
			this.InverseShiftRows(Nb);
			this.addRoundKey(this.state, this.w, 0, Nb);
			this.GeneratePlain();
		}
		this.writePlaintoFile();
	}

	private void writePlaintoFile() {
		try {
			PrintWriter writer = new PrintWriter(this.InputFileName + ".dec", "UTF-8");
			for (int i = 0; i < outputBuffer.size(); i++) {
				// HextoByteArray(outputBuffer.get(i));
				writer.println(outputBuffer.get(i));
			}
			writer.close();
		} catch (Exception ex) {
		}
	}

	private void GeneratePlain() {
		byte[] result = new byte[4 * 4]; // 16 byte ciphertext as required
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				result[i + 4 * j] = this.state[i][j];
			}
		}
		// convert byte array to hex character array
		// 1 byte = 2 hex character
		// System.out.println("Original byte array is: " +
		// Arrays.toString(result));
		char[] hexPlain = new char[result.length * 2];
		for (int i = 0; i < result.length; i++) {
			hexPlain[i * 2] = hexTable[(result[i] & 0xFF) >>> 4];
			hexPlain[i * 2 + 1] = hexTable[(result[i] & 0xFF) & 0x0F];
		}
		String output = new String(hexPlain);
		outputBuffer.add(output);
	}

	private void InverseMixColumns(int Nb) {

	}

	private void InverseShiftRows(int Nb) {
		byte[][] temp = new byte[4][4];

		temp[0][0] = state[0][0];
		temp[1][0] = state[1][3];
		temp[2][0] = state[2][2];
		temp[3][0] = state[3][1];

		temp[0][1] = state[0][1];
		temp[1][1] = state[1][0];
		temp[2][1] = state[2][3];
		temp[3][1] = state[3][2];

		temp[0][2] = state[0][2];
		temp[1][2] = state[1][1];
		temp[2][2] = state[2][0];
		temp[3][2] = state[3][3];

		temp[0][3] = state[0][3];
		temp[1][3] = state[1][2];
		temp[2][3] = state[2][1];
		temp[3][3] = state[3][0];

		for (int i = 0; i < Nb; i++) {
			for (int j = 0; j < Nb; j++) {
				state[i][j] = temp[i][j];
			}
		}
	}

	private void InverseSubBytes(int Nb) {
			for (int i = 0; i < 4; i++) {
				for (int j = 0; j < Nb; j++) {
					state[i][j] = (byte) (sbox[state[i][j] & 0xFF]); //using inverse sbox
				}
			}
	}

	private void keyExpansion(byte[] key) {
		int Nb = 4;
		int Nk = 8; // key length (in words)
		int Nr = 14; // 14 round
		// initialization
		int totalWords = Nb * (Nr + 1);
		this.w = new byte[totalWords][Nb];
		for (int i = 0; i < Nk; i++) {
			for (int j = 0; j < 4; j++) {
				this.w[i][j] = this.key[4 * i + j];
			}
		}

		// remaining words. we start from Nk
		for (int i = Nk; i < totalWords; i++) {

			byte[] tmp = new byte[4];
			for (int k = 0; k < 4; k++) {
				tmp[k] = w[i - 1][k];
			}
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
				result[j] = (byte) (w[i - Nk][j] ^ tmp[j]);
			}
			w[i] = result;
		}
	}

	private byte[] SubWord(byte[] byteArray) {
		for (int i = 0; i < 4; i++) {
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

	private void addRoundKey(byte[][] state, byte[][] w, int Round, int Nb) {
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < Nb; j++) {
				state[i][j] ^= w[Round * Nb + j][i];
			}
		}
	}

	private void GenerateState(byte[] line) {
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				state[i][j] = line[i + 4 * j];
			}
		}
	}
}
