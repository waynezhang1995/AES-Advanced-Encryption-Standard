import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * 
 * @author YuWei (Wayne) Zhang
 * @author Zihan Ye
 *
 */

public class AES_Decryption {

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

	private final char[] sbox_Inverse = { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81,
			0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9,
			0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08,
			0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6,
			0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd,
			0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3,
			0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
			0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf,
			0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c,
			0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe,
			0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f,
			0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f,
			0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae,
			0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6,
			0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

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
	public AES_Decryption(byte[] key, ArrayList<byte[]> source, String inputFileName) {
		this.InputFileName = inputFileName;
		this.hexTable = "0123456789ABCDEF".toCharArray();//hextable for references
		this.key = key;
		this.source = source;
		this.state = new byte[4][4];//state matrix
		this.outputBuffer = new ArrayList<String>();
	}

	/**
	 * This function first calculates subkeys for each round, and 
	 * then execute the main AES decryption algorithm based on 
	 * the pseudo code in AES standard documentation
	 */
	public void decrypt() {
		int Nb = 4;
		int Nr = 14;
		this.keyExpansion(this.key); //calculate subkeys
		for (int i = 0; i < this.source.size(); i++) { //read input file line by line
			byte[] curr = this.source.get(i); //get current line
			this.GenerateState(curr); //generate state matrix
			this.addRoundKey(this.state, this.w, Nr, Nb); //Initial step: addRoundKey
			//we have 13 rounds plus an extra round outside the loop
			for (int j = Nr - 1; j > 0; j--) {
				this.InverseSubBytes(Nb) ;//step 1: InversesubBytes
				this.InverseShiftRows(Nb);//step 2: InverseshiftRows
				this.addRoundKey(this.state, this.w, j, Nb); //step 3: addRoundKey
				this.InverseMixColumns(Nb);//step 4: InversemixColumns
			}
			//14th round
			this.InverseSubBytes(Nb);
			this.InverseShiftRows(Nb);
			this.addRoundKey(this.state, this.w, 0, Nb);
			this.GeneratePlain(); //generate plaintext
		}
		this.writePlaintoFile(); //output to .dec file
	}

	/**
	 * This function outputs plain text to a .dec file
	 */
	private void writePlaintoFile() {
		try {
			PrintWriter writer = new PrintWriter(this.InputFileName + ".dec", "UTF-8");
			for (int i = 0; i < outputBuffer.size(); i++) { //read line by line
				writer.println(outputBuffer.get(i));
			}
			writer.close();
		} catch (Exception ex) {
		}
	}

	/**
	 * This function generates plain text
	 */
	private void GeneratePlain() {
		byte[] result = new byte[4 * 4]; // 16 byte ciphertext as required
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				result[i + 4 * j] = this.state[i][j];
			}
		}
		// convert byte array to hex character array
		// 1 byte = 2 hex character
		char[] hexPlain = new char[result.length * 2];
		for (int i = 0; i < result.length; i++) {
			hexPlain[i * 2] = hexTable[(result[i] & 0xFF) >>> 4];
			hexPlain[i * 2 + 1] = hexTable[(result[i] & 0xFF) & 0x0F];
		}
		String output = new String(hexPlain); //convert to hex character
		outputBuffer.add(output); //add to buffer
	}

	/**
	 * Transformation in the Inverse Cipher that is the inverse of
	 * MixColumns(). 
	 * @param Nb - number of round
	 */
	private void InverseMixColumns(int Nb){
		int[] stateCol = new int[4];
		byte a09 = (byte)0x09; //Multiply 9
		byte a11 = (byte)0x0b; //Multiply 11
		byte a13 = (byte)0x0d; //Multiply 13
		byte a14 = (byte)0x0e; //Multiply 14
		/* Multiply 4x4 matrix and 4x1 maitrix
		 *
		 *     14 11 13 09   *   [s[0][j] s[1][j] s[2][j] s[3][j]]   =   14 * s[0][j] ^ 11 * s[1][j] ^ 13 * s[2][j] ^  9 * s[3][j]
		 *     09 14 11 13												  9 * s[0][j] ^ 14 * s[1][j] ^ 11 * s[2][j] ^ 13 * s[3][j]
		 *     13 09 14 11                                               13 * s[0][j] ^  9 * s[1][j] ^ 14 * s[2][j] ^ 11 * s[3][j]
		 *     11 13 09 14                                               11 * s[0][j] ^ 13 * s[1][j] ^  9 * s[2][j] ^ 14 * s[3][j]
		 */
	    for (int c = 0; c < 4; c++) {
			stateCol[0] = Multiply(a14, state[0][c]) ^ Multiply(a11, state[1][c]) ^ Multiply(a13,state[2][c])  ^ Multiply(a09,state[3][c]);
			stateCol[1] = Multiply(a09, state[0][c]) ^ Multiply(a14, state[1][c]) ^ Multiply(a11,state[2][c])  ^ Multiply(a13,state[3][c]);
			stateCol[2] = Multiply(a13, state[0][c]) ^ Multiply(a09, state[1][c]) ^ Multiply(a14,state[2][c])  ^ Multiply(a11,state[3][c]);
			stateCol[3] = Multiply(a11, state[0][c]) ^ Multiply(a13, state[1][c]) ^ Multiply(a09,state[2][c])  ^ Multiply(a14,state[3][c]);
			for (int i = 0; i < 4; i++){
				state[i][c] = (byte)(stateCol[i]);
			}
		}
	}
	
	/**
	 * Multiply b by a times, can be regard as shift b Multiple digits
	 * @param a
	 * @param b
	 * @return
	 */
	public static byte Multiply(byte a, byte b) {
		byte r = 0;
		int leftmost = 0;
		byte b1 = b;
		byte b2 = b;
		//for 0x80 = 0b1000. Shift 3 digits << 3 
		for(int i=0; i<3; i++){
			leftmost = 0;
			if((b1 & 0x80) == 0x80){
				leftmost = 1;
			}
			b1 = (byte)(b1 << 1);
			if(leftmost == 1){
				b1 = (byte)(b1 ^ 0x1b);
			}
		}
		if(a == 0x09){//0x09 = 0b1001 can be regard as 0b1000 XOR 0b0001
			r= (byte)(b1^b2);
		}else if(a== 0x0b){//0x0b = 0b1011, can be regard as 0b1000 XOR 0b0010 XOR 0b0001
			byte b3 = b;
			leftmost = 0;
			if((b2 & 0x80) == 0x80){
					leftmost = 1;
			}
			b2 = (byte)(b2 <<1);
			if(leftmost==1){
				b2 = (byte) (b2 ^ 0x1b);
			}
			r = (byte)(b1 ^ b2 ^ b3);
		}else if(a== 0x0d){//0x0d = 0b1011 which can be regard as 0b1000 XOR 0b0010 XOR 0b0001
			byte b3 = b;
			for(int i=0; i<2; i++){
				leftmost = 0;
				if((b2 & 0x80) == 0x80){
					leftmost = 1;
				}
				b2 = (byte)(b2 << 1);
				if(leftmost == 1){
					b2 = (byte)(b2 ^ 0x1b);
				}
			}
			r = (byte)(b1 ^ b2 ^ b3);
		}else if(a==0x0e){//0x0e = 0b1110, can be regard as 0b1000 XOR 0b0100 XOR 0b0010
			byte b3 = b;
			//shift left twice
			for(int i=0; i<2; i++){
				leftmost = 0;
				if((b2 & 0x80) == 0x80){
					leftmost = 1;
				}
				b2 = (byte)(b2 << 1);
				if(leftmost == 1){
					b2 = (byte)(b2 ^ 0x1b);
				}
			}
			//shift left once
			leftmost = 0;
			if((b3 & 0x80) == 0x80){
				leftmost = 1;
			}
			b3 = (byte)(b3 << 1);
			if(leftmost == 1){
				b3 = (byte)(b3 ^ 0x1b);
			}	
			r = (byte)(b1 ^ b2 ^ b3);
		}
		return r;
	}

	/**
	 * Transformation in the Inverse Cipher that is the inverse of
	 * ShiftRows(). 
	 * @param Nb - number of round
	 */
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

	/**
	 * Transformation in the Inverse Cipher that is the inverse of
	 * SubBytes(). 
	 * @param Nb - number of round
	 */
	private void InverseSubBytes(int Nb) {
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < Nb; j++) {
				state[i][j] = (byte) (sbox_Inverse[state[i][j] & 0xFF]);
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
			}

			else if (Nk > 6 && i % Nk == 4) {
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
			byteArray[i] = (byte) this.sbox[byteArray[i] & 0xFF];
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
	 * This function generates state matrix
	 * @param line - input ciphertext in bytes
	 */
	private void GenerateState(byte[] line) {
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				state[i][j] = line[i + 4 * j];
			}
		}
	}
}
