import java.io.File;
import java.math.BigInteger;
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
	private static byte[][] context;
	private static final int Rount = 14;

	/**
	 * Constructor
	 */
	public AES(char mode, String key, String inputfile) {
		this.mode = mode;
		this.init(key, inputfile);
	}

	private void init(String key, String inputfile) {
		this.SourceSetUp(key, inputfile);
	}

	private void SourceSetUp(String key, String inputfile) {
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
			int index = 0;
			while (inputfile_Scanner.hasNextLine()) {
				this.context[index] = HextoByteArray(inputfile_Scanner.nextLine().toUpperCase());
				index++;
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
			for (int i = 0; i < HexCharacter.length(); i += 2) {
				byteArray[i / 2] = (byte) ((Character.digit(HexCharacter.charAt(i), 16) << 4)
						+ Character.digit(HexCharacter.charAt(i + 1), 16));
			}
		} catch (Exception ex) {
			throw ex;
		}
		return byteArray;
	}

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
	}
}
