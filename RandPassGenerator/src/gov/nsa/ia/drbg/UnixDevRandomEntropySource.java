package gov.nsa.ia.drbg;

import gov.nsa.ia.util.SelfTestable;

import java.io.*;

/**
 * This class 
 * supports the Get_entropy_input function of SP800-90.
 * This implementation uses the Unix/Linux /dev/random
 * pseudo-file, which delivers quality entropy gathered
 * from internal kernel operations.  This implementation
 * also supports self-test and returning entropy gathered
 * during self-test.
 *
 * This entropy source works only on Linux and Unix systems
 * that support /dev/random.  If called elsewhere, it will 
 * fail.
 * 
 * @author nziring
 */
public class UnixDevRandomEntropySource implements EntropySource, SelfTestable {
	/**
	 * Pseudo-file from which we can get randomness
	 * created by the OS.  Always use "random" not
	 * "urandom", because "urandom" delivers bytes whether
	 * it has entropy for them or not.
	 */
	public static final String DEFAULT_RANDOM_SOURCE = "/dev/random";

	/**
	 * Default buffer size to read from the RANDOM_SOURCE, we
	 * always read this much at a time.  (this is in bytes)
	 */
	public static final int BLOCK_SIZE = 32;

	/**
	 * Expected bits of entropy available from RANDOM_SOURCE
	 * per 32 bytes of data obtained.  Basically, we're
	 * expecting .5 bits of entropy from every bit of
	 * output from system /dev/random.  Since the system
	 * /dev/random on most Unix systems are designed to 
	 * deliver fully conditioned randomness and block 
	 * until it can do so, 0.75 bits is a conservative
	 * bound.
	 */
         public static final int BITS_ENTROPY_PER_BLOCK = 192;

	/**
	 * Reader that grabs bytes from the RANDOM_SOURCE.
	 */
	private BufferedInputStream rinput;

	/**
	 * Random source that this instance uses, normally 
	 * DEFAULT_RANDOM_SOURCE.
	 */
	private String randomSource;
	
	/**
	 * Entropy gathered during self-test
	 */
	private byte[] savedSelfTestEntropy;
	
	/**
	 * True if self-test was called and passed.
	 */
	private boolean passedSelfTest;
	
	/**
	 * Create this EntropySource object, including opening the
	 * random source.  This constructor will throw an IOException
	 * if the underlying random source cannot be opened for
	 * reading.
	 */
	public UnixDevRandomEntropySource() throws IOException {
		this(null);
	}
	
	/**
	 * Create this EntropySource object, using a specified 
	 * random source instead of the default.  This is a very
	 * dangerous operation, because the given random source
	 * does not get tested for quality.  In practice, always
	 * use a high-quality random source like /dev/random.
	 * 
	 * @param randSrc path to a random source generator file
	 */
	
	public UnixDevRandomEntropySource(String randSrc) throws IOException {
		FileInputStream fis;
		if (randSrc == null)
			randomSource = DEFAULT_RANDOM_SOURCE;
		else 
			randomSource = randSrc;

		fis = new FileInputStream(randomSource);
		rinput = new BufferedInputStream(fis, BLOCK_SIZE);
		passedSelfTest = false;
		savedSelfTestEntropy = null;
	}
	
	/**
	 * Return a string representation of this source, for debugging
	 */
	public String toString() {
		return "UnixDevRandomEntropySource[src=" + randomSource + ",blksiz=" + BLOCK_SIZE + "]";
	}
	
	/**
	 * Dispose of this entropy-source, if we are done with it.
	 * After you've called this, all calls to getEntropy will fail.
	 */
	public void dispose() {
		if (rinput != null) try {
			rinput.close();
		} catch(IOException e) { }
		rinput = null;
		passedSelfTest = false;
		savedSelfTestEntropy = null;
		return;
	}

	/**
	 * Get requested entropy.  This method returns the entropy as a byte
	 * array.  It gets the entropy by reading from Linux or Unix /dev/random.
	 * may block until entropy is available.
	 * If the entropy cannot be delivered at all, then STATUS_ERROR
	 * is returned.  If the bit
	 * amount of entropy requested cannot be delivered within
	 * the size limit imposed by maxOutputBytes, then STATUS_ERROR
	 * is returned.  If the dispose() method has been called on this
	 * EntropySource object, then this method always returns null.
	 * 
	 * @param requestedEntropy amount of entropy needed, in bits
	 * @param minOutputBytes minimum amount of output caller will accept, in bytes, usually reqEntropy/8
	 * @param maxOutputBytes maximum amount of output caller will accept, 0 for unlimited
	 * 
	 * @return byte array containing entropy (STATUS_SUCCESS) or null (STATUS_ERROR)
	 */
	public byte[] getEntropy(int requestedEntropyBits, int minOutputBytes,
			int maxOutputBytes) {
		byte[] ret;
		int blocks, tot, cc, bytes;

		if (rinput == null) return null;
		
		blocks = (int) Math.ceil((double) requestedEntropyBits
				/ (double) BITS_ENTROPY_PER_BLOCK);
		// cheesy
		while (minOutputBytes > (blocks * BLOCK_SIZE)) {
			blocks++;
		}
		
		// check to make sure we don't exceed caller-supplied maximum
		if (maxOutputBytes != 0 && (blocks * BLOCK_SIZE) > maxOutputBytes) {
			return null;
		}

		bytes = blocks * BLOCK_SIZE;
		ret = new byte[bytes];
		for (tot = 0; tot < bytes;) {
			cc = 0;
			try {
				cc = rinput.read(ret, tot, (bytes - tot));
			} catch (IOException e) {
				ret = null;
				break;
			}
			tot += cc;
		}
		return ret;
	}
	
	/**
	 * If set to true, performSelfTest will do an extra round
	 * of testing.  This should not be used during normal operation
	 * because it will suck too much entropy out of /dev/random.
	 * This can be used to impose additional self-testing when
	 * examining a new platform.
	 */
	private static boolean LARGE_SELF_TEST = false;

	/**
	 * Perform a basic self-test on this entropy source.
	 * This entails running calling the getEntropy method 
	 * several times and checking that the correct behavior
	 * occurs.  For those calls which generate entropy, we
	 * do a simple byte-entropy computation and make sure it
	 * exceeds a threshold.  
	 *
	 * @return true on success, false on failure
	 */
	public boolean performSelfTest() {
		byte[] ret;
		
		// case 1 - should return null
		ret = getEntropy(512, 6, 6);
		if (ret != null)
			return false;

		// case 2 - should return a byte array of two blocks
		ret = getEntropy(256, BLOCK_SIZE, BLOCK_SIZE*2);
		if (ret.length != (BLOCK_SIZE*2))
			return false;
		if (!EntropyUtil.checkByteEntropy(ret, ret.length, 4.0))
			return false;

		savedSelfTestEntropy = ret;

		// case 3 - should return a byte array of 128 bytes
		// NOTE: case 3 has been disable out to prevent sucking the
		// /dev/random source dry of all its gathered entropy. 
		// To re-enable, set LARGE_SELF_TEST to true.
		if (LARGE_SELF_TEST) {
		    ret = getEntropy(512, 1024 / 8, 1024 / 2);
		    if (ret.length < 1024 / 8)
			return false;
		    if (!EntropyUtil.checkByteEntropy(ret, ret.length, 5.0))
			return false;
		    double chisq;
		    chisq = EntropyUtil.chiSquaredStatistic(ret, ret.length, 2);
		    System.err.println("DEBUG***1a - chisq for 2 bit chunks = " + chisq);
		    if (!EntropyUtil.testChiSquared(chisq, 2)) {
			System.err.println("DEBUG***1d - chisq would fail for 2 bits");
		    }
		    chisq = EntropyUtil.chiSquaredStatistic(ret, ret.length, 3);
		    System.err.println("DEBUG***1a - chisq for 3 bit chunks = " + chisq);
		    if (!EntropyUtil.testChiSquared(chisq, 3)) {
			System.err.println("DEBUG***1d - chisq would fail for 3 bits");
		    }
		    chisq = EntropyUtil.chiSquaredStatistic(ret, ret.length, 4);
		    System.err.println("DEBUG***1b - chisq for 4 bit chunks = " + chisq);
		    if (!EntropyUtil.testChiSquared(chisq, 4)) {
			System.err.println("DEBUG***1d - chisq would fail for 4 bits");
		    }
		    chisq = EntropyUtil.chiSquaredStatistic(ret, ret.length, 5);
		    System.err.println("DEBUG***1c - chisq for 5 bit chunks = " + chisq);
		    if (!EntropyUtil.testChiSquared(chisq, 5)) {
			System.err.println("DEBUG***1d - chisq would fail for 5 bits");
		    }

		}		

		passedSelfTest = true;
		return true;
	}
	
	/**
	 * Return entropy gathered during self-test (case 2).  The block
	 * returned will be of size 2*BLOCK_SIZE, and will have passed a
	 * basic check performed by EntropyUtil.checkByteEntropy that its
	 * entropy is at least 4 bits per byte.  If performSelfTest has 
	 * not been called, or if the self-test failed, or if dispose
	 * has been called, then this method will return null.
	 * 
	 * @return byte array containing entropy from self-test, or null
	 */
	public byte[] getSelfTestEntropy() {
	    if (passedSelfTest && savedSelfTestEntropy != null) {
		byte copy[];
		copy = new byte[savedSelfTestEntropy.length];
		System.arraycopy(savedSelfTestEntropy, 0, copy, 0, copy.length);
		return copy;
	    }
	    else 
		return null;
	}	


	private static final int TEST_SIZES[] = { 128, 256, 384, 512};
	/**
	 * Simple unit test main method, 
	 * simply creates an instance and calls
	 * performSelfTest().  Then it calls getEntropy
	 * and prints the output.  If there is a command-line
	 * argument, then additional self-test will be
	 * performed.
	 */
	public static void main(String[] args) {
		UnixDevRandomEntropySource rsrc;
		int i;
		byte [] output;
		double h;
		
		if (args.length > 0) {
		    System.err.println("Non-empty list of command-line args supplied.");
		    System.err.println("Setting up additional self-test.");
		    LARGE_SELF_TEST = true;
		}

		try {
			System.err.println("About to call self-test method.");
			rsrc = new UnixDevRandomEntropySource();
			if (rsrc.performSelfTest()) {
				System.err.println("Self-Test Passed!");
			}
			else {
				System.err.println("Self-test failed.");
				System.exit(1);
			}
		} catch (IOException ie2) {
			System.err.println("Error creating random source: " + ie2);
			ie2.printStackTrace();
		}

		
		try {
			rsrc = new UnixDevRandomEntropySource(((args.length > 0)?(args[0]):(null)));
			for(i = 0; i < TEST_SIZES.length; i++) {
				output = rsrc.getEntropy(TEST_SIZES[i], TEST_SIZES[i]/8, 0);
				System.err.println("Test at size " + TEST_SIZES[i] + " returns array of " +
						output.length + " bytes.");
				h = EntropyUtil.computeByteEntropy(output, output.length);
				System.err.println("    byte entropy = " + h + " bits");
			}
			rsrc.dispose();
		}
		catch(IOException ie) {
			System.err.println("Error creating random source: " + ie);
			ie.printStackTrace();
		}
		

	}

}
