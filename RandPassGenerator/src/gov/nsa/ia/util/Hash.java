package gov.nsa.ia.util;

import gov.nsa.ia.drbg.DRBGConstants;

import java.security.*;
import java.math.BigInteger;
import java.io.*;

/**
 * An instance of the Hash class encapsulates a
 * java.security.MessageDigest object, and provides
 * the ability to hash a value represented in
 * several ways.  It also provides the Hash_df
 * function from SP800-90 section 10.4.1.
 * This class also implements a self-test method.
 * 
 * @author nziring
 */
public class Hash implements DRBGConstants, SelfTestable {
	private MessageDigest md;

	private int outputBytes;

	/**
	 * Supported bit strengths.  This array must parallel
	 * the ALGORITHM_VALUES array.
	 */
        static final int[] SIZE_VALUES = { 160, 256, 384, 512 };

	/**
	 * Algorithm to use for each bit strength.  This array
	 * must parallel the SIZE_VALUES array.
	 */
        static final String[] ALGORITHM_VALUES = { "SHA-1", "SHA-256",
						   "SHA-384", "SHA-512" };

	/**
	 * Default bit strength 
	 */
	public static final int DEFAULT_SIZE = 256;

	/**
	 * Maximum bit strength supported
	 */
	public static final int MAX_SIZE = 512;
	
	/**
	 * Create an instance of the Hash class using
	 * the default bit strength.
	 * 
	 * @throws RuntimeException if algorithm not available
	 */
	public Hash() {
		this(DEFAULT_SIZE);
	}

	/**
	 * Create an instance of the Hash class, for the
	 * supplied bit strength.  If the bit strength is
	 * given as 0, then the DEFAULT_SIZE is used.
	 * The size given must be one of the allowed SIZE_VALUES
	 * or may be 0; otherwise IllegalArgumentException is
	 * thrown.
	 *
	 * @throws IllegalArgumentException on bad argument
	 * @throws RuntimeException if algorithm not available
	 */
	public Hash(int size) {
		int i;
		String alg = null;

		if (size == 0)
			size = DEFAULT_SIZE;

		for (i = 0; i < SIZE_VALUES.length; i++) {
			if (size == SIZE_VALUES[i])
				alg = ALGORITHM_VALUES[i];
		}
		if (alg == null) {
			throw new IllegalArgumentException(
					"Hash constructor - invalid size specified");
		}

		try {
			md = MessageDigest.getInstance(alg);
		} catch (NoSuchAlgorithmException nsae) {
			/* this should only happen if the crypto package is not
			 * properly installed.
			 */
			throw new RuntimeException("Algorithm " + alg + " not installed.");
		}
		outputBytes = size / 8; /* assume all hashes have output that is an even number of bytes */
	}

	/**
	 * Re-initialize the hash.  This calls the reset()
	 * method of the underlying java.security.MessageDigest.
	 */
	public int reset() {
		md.reset();
		return STATUS_SUCCESS;
	}

	/**
	 * Update the hash with a single byte.
	 */
	public int update(byte b) {
		md.update(b);
		return STATUS_SUCCESS;
	}

	/**
	 * Update the hash with an array of bytes, this is
	 * the same as update(ba, 0, ba.length).
	 */
	public int update(byte[] ba) {
		return update(ba, 0, ba.length);
	}

	/**
	 * Update the hash with part of an array of bytes.
	 */
	public int update(byte[] ba, int offset, int length) {
		md.update(ba, offset, length);
		return STATUS_SUCCESS;
	}

	/**
	 * Update the hash with the bytes of a big integer - note that this
	 * converts the BigInteger to bytes in the default manner, which is
	 * usually wrong.  Do the conversion yourself instead.
	 */
	private int update(BigInteger bi) {
		md.update(bi.toByteArray());
		return STATUS_SUCCESS;
	}

	/**
	 * Return the correct number of bytes to hold
	 * the output of this message digest.
	 */
	public int getDigestSize() {
		return outputBytes;
	}

	/**
	 * Return the digest into a byte array.  STATUS_ERROR
	 * is returned if the array is too small.
	 */
	public int getDigest(byte[] digest) {
		return getDigest(digest, 0);
	}

	/**
	 * Return the digest into a byte array.  STATUS_ERROR
	 * is returned if the array is too small.
	 */
	public int getDigest(byte[] digest, int offset) {
		if (outputBytes > digest.length - offset)
			return STATUS_ERROR;
		byte[] result;
		result = md.digest();
		if (result == null || result.length != outputBytes)
			return STATUS_ERROR;

		System.arraycopy(result, 0, digest, offset, outputBytes);
		return STATUS_SUCCESS;
	}
	
	/**
	 * Hash-derivation-function is an auxiliary function defined in 
	 * Sp800-90 sect 10.4.1.  It accepts a value to hash, and a
	 * desired output length (in bits), and uses an interative
	 * algorithm to build up a bitstring until the bitstring is
	 * long enough to satisfy the requested output length.
	 * In this implementation, the output length must be a 
	 * multiple of 8, because we return a byte array.
	 * Note that this method always resets the Hash object before
	 * beginning the Hash_df algorithm, so any intermediate hash
	 * state will be gone!
	 * 
	 * @param input input data to be hashed
	 * @param reqOutputBits desired output bits
	 * @param output output byte array, large enough to hold reqOutputBits (normally, size will be exactly reqOutputBits/8)
	 */
	public int hash_df(byte [] input,  int reqOutputBits, byte [] output) {
		byte[] temp;
		int outlen, len;
		byte counter;
		int status;
		
		if ((reqOutputBits % 8) != 0) {
			return STATUS_ERROR;
		}
		
		outlen = getDigestSize() * 8;
		len =  (int)Math.ceil((double)reqOutputBits / (double)outlen);
		if (reqOutputBits > (8 * output.length)) {
		    // buffer too small to hold result!
			return STATUS_ERROR;
		}

		status = STATUS_SUCCESS;
		temp = new byte[len * getDigestSize()];
		for(counter = 1; counter <= len; counter++) {
			if (reset() != STATUS_SUCCESS) status = STATUS_ERROR;
			if (update(counter) != STATUS_SUCCESS) status = STATUS_ERROR;
			if (update((byte)(reqOutputBits >> 24)) != STATUS_SUCCESS) status = STATUS_ERROR;
			if (update((byte)(reqOutputBits >> 16)) != STATUS_SUCCESS) status = STATUS_ERROR;
			if (update((byte)(reqOutputBits >> 8)) != STATUS_SUCCESS) status = STATUS_ERROR;
			if (update((byte)(reqOutputBits >> 0)) != STATUS_SUCCESS) status = STATUS_ERROR;
			if (update(input) != STATUS_SUCCESS) status = STATUS_ERROR;
			// fixed incorrect offset below
			if (getDigest(temp, getDigestSize() * (counter - 1)) != STATUS_SUCCESS) status = STATUS_ERROR;
		}
		
		if (status == STATUS_SUCCESS) {
			System.arraycopy(temp, 0, output, 0, reqOutputBits / 8);
		}
		return STATUS_SUCCESS;
	}

	// self-test support
	private static int[] test_sizes = { 160, 256, 512 };

        // specific self-test inputs fro SP800-57
	private static byte[][] test_inputs = {
			{ (byte) 'a', (byte) 'b', (byte) 'c' },
			{ (byte) 'a', (byte) 'b', (byte) 'c' },
			{ (byte) 'a', (byte) 'b', (byte) 'c' }, };

        // specific self-test outputs from SP800-57
	private static byte[][] test_outputs = {
			{ (byte) 0xa9, (byte) 0x99, (byte) 0x3e, (byte) 0x36, (byte) 0x47,
					(byte) 0x06, (byte) 0x81, (byte) 0x6a, (byte) 0xba,
					(byte) 0x3e, (byte) 0x25, (byte) 0x71, (byte) 0x78,
					(byte) 0x50, (byte) 0xc2, (byte) 0x6c, (byte) 0x9c,
					(byte) 0xd0, (byte) 0xd8, (byte) 0x9d },
			{ (byte) 0xba, (byte) 0x78, (byte) 0x16, (byte) 0xbf, (byte) 0x8f,
					(byte) 0x01, (byte) 0xcf, (byte) 0xea, (byte) 0x41,
					(byte) 0x41, (byte) 0x40, (byte) 0xde, (byte) 0x5d,
					(byte) 0xae, (byte) 0x22, (byte) 0x23, (byte) 0xb0,
					(byte) 0x03, (byte) 0x61, (byte) 0xa3, (byte) 0x96,
					(byte) 0x17, (byte) 0x7a, (byte) 0x9c, (byte) 0xb4,
					(byte) 0x10, (byte) 0xff, (byte) 0x61, (byte) 0xf2,
					(byte) 0x00, (byte) 0x15, (byte) 0xad },
			{ (byte) 0xdd, (byte) 0xaf, (byte) 0x35, (byte) 0xa1, (byte) 0x93,
					(byte) 0x61, (byte) 0x7a, (byte) 0xba, (byte) 0xcc,
					(byte) 0x41, (byte) 0x73, (byte) 0x49, (byte) 0xae,
					(byte) 0x20, (byte) 0x41, (byte) 0x31, (byte) 0x12,
					(byte) 0xe6, (byte) 0xfa, (byte) 0x4e, (byte) 0x89,
					(byte) 0xa9, (byte) 0x7e, (byte) 0xa2, (byte) 0x0a,
					(byte) 0x9e, (byte) 0xee, (byte) 0xe6, (byte) 0x4b,
					(byte) 0x55, (byte) 0xd3, (byte) 0x9a, (byte) 0x21,
					(byte) 0x92, (byte) 0x99, (byte) 0x2a, (byte) 0x27,
					(byte) 0x4f, (byte) 0xc1, (byte) 0xa8, (byte) 0x36,
					(byte) 0xba, (byte) 0x3c, (byte) 0x23, (byte) 0xa3,
					(byte) 0xfe, (byte) 0xeb, (byte) 0xbd, (byte) 0x45,
					(byte) 0x4d, (byte) 0x44, (byte) 0x23, (byte) 0x64,
					(byte) 0x3c, (byte) 0xe8, (byte) 0x0e, (byte) 0x2a,
					(byte) 0x9a, (byte) 0xc9, (byte) 0x4f, (byte) 0xa5,
					(byte) 0x4c, (byte) 0xa4, (byte) 0x9f,

			}, };

	/**
	 * Perform a self-test on the hash algorithms.
	 * This method creates several instances of the
	 * Hash class internally, then calls various
	 * methods and
	 * checks that they return the correct answers
	 * as specified in the official test vectors.
	 * If they don't then we return false, else we
	 * return true.  Note that calling this ONCE
	 * tests all supported sizes of hash.  The
	 * correct way to invoke this is:
	 * <tt>
	 *    boolean testresult = (new Hash()).performSelfTest()
	 * </tt>
	 */
	public boolean performSelfTest() {
		Hash h;
		byte[] result;
		int i, j;

		for (i = 0; i < test_sizes.length; i++) {
			try {
				h = new Hash(test_sizes[i]);
			} catch (Exception e) {
				return false;
			}

			if (h.update(test_inputs[i]) != STATUS_SUCCESS) {
				return false;
			}
			result = new byte[h.getDigestSize()];
			if (h.getDigest(result) != STATUS_SUCCESS) {
				return false;
			}
			if (!java.util.Arrays.equals(result, test_outputs[i])) {
				return false;
			}

			if (h.reset() != STATUS_SUCCESS) {
				return false;
			}

			for (j = 0; j < test_inputs[i].length; j++) {
				if (h.update(test_inputs[i][j]) != STATUS_SUCCESS) {
					return false;
				}
			}
			if (h.getDigest(result) != STATUS_SUCCESS) {
				return false;
			}
			if (!java.util.Arrays.equals(result, test_outputs[i])) {
				return false;
			}
		}

		return true;
	}

	/**
	 * This main method performs unit testing for the
	 * hash class, by calling its self-test method if
	 * no args are given, or by hashing each command-line
	 * argument if args are given.  The hash is comnputed
	 * at each allowed bit strength.
	 *
	 * @param args list of strings
	 */
	public static void main(String[] args) {
		if (args.length == 0) {
			Hash h = new Hash();
			System.err.println("Performing self-test, please wait.");
			boolean pass = h.performSelfTest();
			System.err.println("Self test finished, pass=" + pass);
			
			h = new Hash(DEFAULT_SIZE);
			byte [] output;
			byte [] input;
			int len;
			
			len = 880;
			input = "foobar".getBytes();
			output = new byte[len / 8];
			if (h.hash_df(input, len, output) == STATUS_SUCCESS) {
				// need to get test vectors for this and move it into performSelfTest()
				System.err.println("Hash_df function test succeeded.");
			} else {
				System.err.println("Hash_df function test failed.");
			}
			return;
		}
		else if (args.length == 2) {
		    int siz = 256;
		    try {
			siz = Integer.parseInt(args[0]);
		    } catch (NumberFormatException nfe) {
			System.err.println("Bad size for 2-arg version of this test main");
			System.err.println("Usage: java Hash size hexstring   (size usually 256 or 384)");
			System.exit(1);
		    }
		    BigInteger v;
		    v = new BigInteger(args[1], 16);

		    Hash hx = new Hash(siz);

		    int status;
		    status = hx.reset();
		    if (status != STATUS_SUCCESS) {
			System.err.println("Hash reset failed.");
			System.exit(2);
		    }
		    byte [] databuf = pbi2ba(v);
		    status = hx.update(databuf);
		    if (status != STATUS_SUCCESS) {
			System.err.println("Hash update failed.");
			System.exit(2);
		    }

		    byte [] output = new byte[hx.getDigestSize()];
		    status = hx.getDigest(output);
		    if (status != STATUS_SUCCESS) {
			System.err.println("Hash getDigest failed.");
			System.exit(2);
		    }
		    
		    System.err.println("For size " + siz + " and input " + bufferToString(databuf) + " output digest is " + bufferToString(output));
		}
		else {
			try {
				FileInputStream fis;
				fis = new FileInputStream(args[0]);
				
				Hash hx[] = new Hash[SIZE_VALUES.length];
				
				int i;
				for(i = 0; i < SIZE_VALUES.length; i++) {
					hx[i] = new Hash(SIZE_VALUES[i]);
				}
				
				int cc;
				byte buf[] = new byte[2048];
				for(cc = fis.read(buf); cc > 0; cc = fis.read(buf)) {
					for(i = 0; i < hx.length; i++) {
						if (hx[i].update(buf, 0, cc) != STATUS_SUCCESS) {
							fis.close();
							System.err.println("Error updating " +
											ALGORITHM_VALUES[i] + " hash.");
							System.exit(0);
						}
					}
				}
				fis.close();
				
				byte [] result;
				for(i = 0; i < hx.length; i++) {
					result = new byte[hx[i].getDigestSize()];
					if (hx[i].getDigest(result) != STATUS_SUCCESS) {
						System.err.println("Error getting output from " +
											ALGORITHM_VALUES[i] + " hash.");
						System.exit(0);						
					}
					int b;
					System.err.println("Digest of file " + args[0] + " using " +
							ALGORITHM_VALUES[i] + " hash is: ");
					for(b = 0; b < result.length; b++) {
						System.err.print(" " + Integer.toString((int)result[b] & 0x00ff, 16));
					}
					System.err.println(".");
				}
				
			}
			catch (IOException e) {
				System.err.println("IO Error in file test: " + e);
				e.printStackTrace();
			}

		}

	}

        private static byte [] pbi2ba(java.math.BigInteger bi) {
   	    byte [] tmp;
	    //int offset;

	    tmp = bi.toByteArray();

	    byte [] ret;

	    if ((tmp.length > 1) && (tmp[0] == (byte)0) &&
		((tmp[1] & (byte)0x80) != 0)) {
		// in this case, byte array has extra 00 byte prepended,
		// so remove it
		ret = new byte[tmp.length - 1];
		System.arraycopy(tmp, 1, ret, 0, tmp.length - 1);
	    } else {
		ret = tmp;
	    }

	    return ret;
	}

	private static char nib[] = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', 
		'9', 'a', 'b', 'c', 'd', 'e', 'f'
	};

	private static String bufferToString(byte [] b) {
		StringBuilder sb = new StringBuilder(b.length * 2);
		int i;
		for(i = 0; i < b.length; i++) {
			sb.append(nib[(((int)b[i]) & 0x0f0) >> 4]);
			sb.append(nib[(((int)b[i]) & 0x0f)]);
		}
		return sb.toString();
	}

}
