import java.io.File;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Scanner;

/**
 * 
 * @author YuWei (Wayne) Zhang V00805647
 * @author Zihan Ye
 * 
 */

public class AES {

	private static char mode;
	private static byte[] key;
	private static ArrayList<byte[]> context;
	private static final int Round = 14;
	private String inputFileName;

	/**
	 * Constructor
	 * @param mode - e or d
	 * @param key - input keyFile name
	 * @param inputfile - input inputFile name
	 */
	public AES(char mode, String key, String inputfile) {
		this.mode = mode;
		this.context = new ArrayList<byte[]>();
		this.init(key, inputfile);
	}

	private void init(String key, String inputfile) {
		this.SourceSetUp(key, inputfile);
	}

	/**
	 * Program core. This function either encryption/decryption based on input mode
	 */
	private void Calculate() {
		if (this.mode == 'e') {
			AES_Encryption encryption = new AES_Encryption(this.key, this.context,this.inputFileName);
			encryption.encrypt();
		} else if (this.mode == 'd') {
			AES_Decryption decryption = new AES_Decryption(this.key, this.context,this.inputFileName);
			decryption.decrypt();
		}
	}

	/**
	 *  This function scanners files and convert to byte arrays
	 * @param key
	 * @param inputfile
	 */
	private void SourceSetUp(String key, String inputfile) {
		this.inputFileName = inputfile;
		Scanner key_Scanner;
		Scanner inputfile_Scanner;
		// scanner key and plaintext file
		try {
			key_Scanner = new Scanner(new File(key));
			inputfile_Scanner = new Scanner(new File(inputfile));

			// convert key to byte array
			// key contains a single line of 64 hex characters, which represents
			// a 256-bit key
			this.key = HextoByteArray(key_Scanner.nextLine().toUpperCase());

			// convert input file to byte array line by line
			while (inputfile_Scanner.hasNextLine()) {
				String line = inputfile_Scanner.nextLine();
				this.context.add(HextoByteArray(line.toUpperCase()));
			}

		} catch (Exception ex) {
			ErrorHandler(ex.toString());
		}
	}

	/**
	 * Convert hex string to byte array
	 * 
	 * @param key
	 * @param inputfile
	 */
	private byte[] HextoByteArray(String HexCharacter) {
		byte[] byteArray = new byte[HexCharacter.length() / 2];
		// check if input contains any non-hex character
		if (!HexCharacter.matches("-?[0-9a-fA-F]+")) {
			ErrorHandler("Input string contains non-hex character");
		}
		// check length
		if (HexCharacter.length() < 32) {
			ErrorHandler("Input string is less than 32 hex characters");
		}

		try {
			for (int i = 0; i < byteArray.length; i++) {
				int index = i * 2;
				int v = Integer.parseInt(HexCharacter.substring(index, index + 2), 16);
				byteArray[i] = (byte) v;
			}

		} catch (Exception ex) {
			throw ex;
		}
		return byteArray;
	}

	/**
	 * Print error message 
	 * @param error - error
	 */
	private static void ErrorHandler(String error) {
		System.err.println(error);
		System.exit(0);
	}

	public static void main(String[] args) {

		if (args.length != 3) {
			ErrorHandler("Insufficient Arguments ! \nUsage: java AES <mode> <key> <source>");
		}
		if (!args[0].equals("e") && !args[0].equals("d")) {
			ErrorHandler("Incorrect mode ! \n('d' for Decryption, 'e' for Encryption)");
		}
		// Ok mode key file text file
		AES aes = new AES(args[0].charAt(0), args[1], args[2]);
		aes.Calculate();
	}
}
