import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * @author YuWei (Wayne) Zhang
 * @author Zihan Ye
 */

public class AES_Encryption {

	private final char[] hexTable;
	private byte[] key;
	private byte[][] state;
	private byte[][] w;
	private String InputFileName;
	private ArrayList<byte[]> source;
	private ArrayList<String> outputBuffer;

	private final char[] sbox = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
			0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
			0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7,
			0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a,
			0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc,
			0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
			0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6,
			0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
			0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e,
			0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
			0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78,
			0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66,
			0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9,
			0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
			0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

	private final char[][] Rcon = { { 0x00, 0x00, 0x00, 0x00 }, { 0x01, 0x00, 0x00, 0x00 }, { 0x02, 0x00, 0x00, 0x00 },
			{ 0x04, 0x00, 0x00, 0x00 }, { 0x08, 0x00, 0x00, 0x00 }, { 0x10, 0x00, 0x00, 0x00 },
			{ 0x20, 0x00, 0x00, 0x00 }, { 0x40, 0x00, 0x00, 0x00 }, { 0x80, 0x00, 0x00, 0x00 },
			{ 0x1b, 0x00, 0x00, 0x00 }, { 0x36, 0x00, 0x00, 0x00 } };

	/**
	 * 
	 * @param key - in bytes
	 * @param source - each line is converted to byte array, and then insert into arraylist
	 * @param inputFileName - absolute path of inputFile
	 */
	public AES_Encryption(byte[] key, ArrayList<byte[]> source, String inputFileName) {
		this.InputFileName = inputFileName;
		this.hexTable = "0123456789ABCDEF".toCharArray(); //hextable for references
		this.key = key;
		this.source = source;
		this.state = new byte[4][4]; //state matrix
		this.outputBuffer = new ArrayList<String>(); 
	}

	/**
	 * This function first calculates subkeys for each round, and 
	 * then execute the main AES encryption algorithm based on 
	 * the pseudo code in AES standard documentation
	 */
	public void encrypt() {
		int Nb = 4;
		int Nr = 14;
		this.keyExpansion(this.key); //calculate subkeys
		for (int i = 0; i < this.source.size(); i++) { //read input file line by line
			byte[] curr = this.source.get(i);	//get current line
			this.GenerateState(curr);	//generate state matrix
			this.addRoundKey(this.state, this.w, 0, Nb); //Initial step: addRoundKey
			//we have 13 rounds plus an extra round outside the loop
			for (int j = 1; j < Nr; j++) {
				this.subBytes(Nb); //step 1: subBytes
				this.shiftRows(Nb); //step 2: shiftRows
				this.MixColumns(Nb); //step 3: mixColumns
				this.addRoundKey(this.state, this.w, j, Nb); //step 4: addRoundKey
			}
			//14th round
			this.subBytes(Nb);
			this.shiftRows(Nb);
			this.addRoundKey(this.state, this.w, Nr, Nb);
			this.GenerateCipher(); //generate cipher message in bytes
		}
		this.writeCiphertoFile(); //output to <inputFile>.enc file
	}

	/**
	 * This function outputs cipher text to a .enc file
	 */
	private void writeCiphertoFile() {
		try {
			PrintWriter writer = new PrintWriter(this.InputFileName + ".enc", "UTF-8");
			for (int i = 0; i < outputBuffer.size(); i++) { //read ciphers line by line
				writer.println(outputBuffer.get(i));
			}
			writer.close();
		} catch (Exception ex) {
		}
	}

	/**
	 * This function generates cipher text
	 */
	private void GenerateCipher() {
		byte[] result = new byte[4 * 4]; // 16 byte ciphertext as required
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				result[i + 4 * j] = this.state[i][j]; //covert state matrix to cipertext array 
			}
		}
		// convert byte array to hex character array
		// 1 byte = 2 hex character
		char[] hexCipher = new char[result.length * 2];
		for (int i = 0; i < result.length; i++) {
			hexCipher[i * 2] = hexTable[(result[i] & 0xFF) >>> 4];
			hexCipher[i * 2 + 1] = hexTable[(result[i] & 0xFF) & 0x0F];
		}
		String output = new String(hexCipher); //convert to hex character
		outputBuffer.add(output); //add to buffer
	}

	/**
	 * This function generates state matrix
	 * @param line - input plaintext in bytes
	 */
	private void GenerateState(byte[] line) {
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				state[i][j] = line[i + 4 * j];
			}
		}
	}

	/**
	 * This function based on the pseudo code in AES standard documentation (section 5.2)
	 * @param key - input key in bytes
	 */
	private void keyExpansion(byte[] key) {
		int Nb = 4;
		int Nk = 8; // key length (in words)
		int Nr = 14; // 14 round
		// initialization
		int totalWords = Nb * (Nr + 1);
		this.w = new byte[totalWords][Nb];
		//copy first 16 bytes to w
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

	/**
	 * Helper method for key expansion
	 * Substitute corresponding byte in SBOX
	 * @param byteArray - input
	 * @return byte array after substitution
	 */
	private byte[] SubWord(byte[] byteArray) {
		for (int i = 0; i < 4; i++) {
			byteArray[i] = (byte) this.sbox[byteArray[i] & 0xFF]; //make sure it is positive 
		}
		return byteArray;
	}

	/**
	 * Shift one byte left
	 * @param byteArray - input
	 * @return byte array after byte shift 
	 */
	private byte[] rotWord(byte[] byteArray) {
		byte[] tmp = new byte[4];
		for (int i = 0; i < 3; i++) {
			tmp[i] = byteArray[i + 1];
		}
		tmp[3] = byteArray[0];
		byteArray = tmp;
		return byteArray;
	}

	/**
	 * In the AddRoundKey() transformation, a Round Key is added to the State by a simple bitwise
	 * XOR operation
	 * @param state - state matrix
	 * @param w - subkeys
	 * @param Round - current round 
	 * @param Nb - number of round
	 */
	private void addRoundKey(byte[][] state, byte[][] w, int Round, int Nb) {
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < Nb; j++) {
				state[i][j] ^= w[Round * Nb + j][i];
			}
		}
	}

	/**
	 * The SubBytes() transformation is a non-linear byte substitution that operates independently
	 * on each byte of the State using a substitution table (S-box).
	 * @param Nb - number of round
	 */
	private void subBytes(int Nb) {
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < Nb; j++) {
				state[i][j] = (byte) (sbox[state[i][j] & 0xFF]);
			}
		}
	}

	/**
	 * Transformation in the Cipher that processes the State by cyclically
	 * shifting the last three rows of the State by different offsets. 
	 * @param Nb - number of round
	 */
	private void shiftRows(int Nb) {
		byte[][] temp = new byte[4][4];

		temp[0][0] = state[0][0];
		temp[1][0] = state[1][1];
		temp[2][0] = state[2][2];
		temp[3][0] = state[3][3];

		temp[0][1] = state[0][1];
		temp[1][1] = state[1][2];
		temp[2][1] = state[2][3];
		temp[3][1] = state[3][0];

		temp[0][2] = state[0][2];
		temp[1][2] = state[1][3];
		temp[2][2] = state[2][0];
		temp[3][2] = state[3][1];

		temp[0][3] = state[0][3];
		temp[1][3] = state[1][0];
		temp[2][3] = state[2][1];
		temp[3][3] = state[3][2];

		//copy back to state matrix
		for (int i = 0; i < Nb; i++) {
			for (int j = 0; j < Nb; j++) {
				state[i][j] = temp[i][j];
			}
		}
	}

	/**
	 * Transformation in the Cipher that takes all of the columns of the
	 * State and mixes their data (independently of one another) to
	 * produce new columns. 
	 * @param Nb - number of round
	 */
	private void MixColumns(int Nb) {
		int[] stateCol = new int[4];
		byte a02 = (byte) 0x02; //multiply 2
		byte a03 = (byte) 0x03; //multiply 3

		/*
		 * multiply the 4x4 matrix and 4x1 matrix
		 * 
		 *    2 3 1 1   *   s[0][j] s[1][j] s[2][j] s[3][j]   =   (2 * s[0][j]) ^ (3 * s[1][j]) ^ s[2][j] ^ s[3][j]
		 *    1 2 3 1                                             s[0][j] ^ (2 * s[1][j]) ^ (3 * s[2][j]) ^ s[3][j]
		 *    1 1 2 3                                             s[0][j] ^ s[1][j] ^ (2 * s[2][j]) ^ (3 * s[3][j])
		 *    3 1 1 2                                             (3 * s[0][j]) ^ s[1][j] ^ s[2][j] ^ (2 * s[3][j])
		 */
		for (int j = 0; j < Nb; j++) {
			stateCol[0] = Multiply(a02, state[0][j]) ^ Multiply(a03, state[1][j]) ^ state[2][j] ^ state[3][j];
			stateCol[1] = state[0][j] ^ Multiply(a02, state[1][j]) ^ Multiply(a03, state[2][j]) ^ state[3][j];
			stateCol[2] = state[0][j] ^ state[1][j] ^ Multiply(a02, state[2][j]) ^ Multiply(a03, state[3][j]);
			stateCol[3] = Multiply(a03, state[0][j]) ^ state[1][j] ^ state[2][j] ^ Multiply(a02, state[3][j]);
			// update each column into the state
			for (int i = 0; i < Nb; i++) {
				state[i][j] = (byte) (stateCol[i]);
			}
		}
	}

	public static byte Multiply(byte a, byte b) {
		byte r = 0x00;
		byte temp = b;
		int leftmost = 0;
		// see if the leftmost digit is 1
		if ((temp & 0x80) == 0x80) {
			leftmost = 1;
		}
		if (a == 0x02) {// multiply by 2
			temp = (byte) (temp << 1);
			// if leftmost is 1 before shifting, XOR 0x1b
			if (leftmost == 1) {
				temp = (byte) (temp ^ 0x1b);
			}
			r = temp;
		} else if (a == 0x03) {// multiply by 3
			r = temp;
			temp = (byte) ((temp << 1));
			// if leftmost is 1 before shifting, XOR 0x1b
			if (leftmost == 1) {
				temp = (byte) (temp ^ 0x1b);
			}
			r = (byte) (r ^ temp);
		}
		return r;
	}
}
