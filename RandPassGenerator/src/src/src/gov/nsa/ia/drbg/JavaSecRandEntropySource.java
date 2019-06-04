package gov.nsa.ia.drbg;

import gov.nsa.ia.util.SelfTestable;

import java.security.SecureRandom;
import java.security.GeneralSecurityException;

/**
 * This class supports the Get_entropy_input function
 * of SP800-90.  This implementation uses multiple instances
 * of the Java java.security.SecureRandom  generator, which
 * uses entropy gathered from an OS-specific mechanism or
 * mechanisms.  Note that we use the generateSeed() method, 
 * which grabs raw system entroy, so it may block.
 *
 * This implementation also supports self-test.
 *
 * This entropy source is suitable for use on most operating
 * systems where Java runs, including Linux and Windows.  But
 * note that it sucks up system entropy fairly aggressively, 
 * so don't be surprised if it blocks.
 *
 * @author nziring
 */

public class JavaSecRandEntropySource implements EntropySource, SelfTestable {

    /**
     * How many separate SecureRandom instances to use.
     */
    public static final int DEFAULT_SOURCES = 2;

    /**
     * Default number of bytes to generate at a time, evenly split 
     * across the number of SecureRandom instances.   Must be an even
     * mulitple of DEFAULT_SOURCES.
     */
    public static final int BLOCK_SIZE = 16;

    /**
     * Expected bits of entropy available from the SecureRandom
     * sources per BLOCK_SIZE bytes of entropy obtained from the
     * SecureRandom generateSeed.
     * We assume that all the bits are good, because the HashDRBG 
     * already asks for lots of extra, so we assume full goodness
     * here.
     */
    public static final int BITS_ENTROPY_PER_BLOCK = 128;

    /**
     * Sources list
     */
    private SecureRandom sources[];

    /**
     * Entropy gathered during self-test
     */
    private byte[] savedSelfTestEntropy;
	
    /**
     * True if self-test was called and passed.
     */
    private boolean passedSelfTest;
	
    /**
     * Create this EntropySource object, including initializing
     * the underlying SecureRandom source objects.
     *
     * May throw a GeneralSecurityException if the underlying 
     * crypto subsystem is unable to instantiate a SecureRandom
     * object.
     */
    public JavaSecRandEntropySource() throws GeneralSecurityException {
	sources = new SecureRandom[DEFAULT_SOURCES];

	int i;
	for(i = 0; i < DEFAULT_SOURCES; i++) {
	    sources[i] = new SecureRandom();
	    
	}

	passedSelfTest = false;
	savedSelfTestEntropy = null;
    }

    /**
     * Return a string representation of this source, for debugging
     * and logging.
     */
    public String toString() {
	StringBuilder sb = new StringBuilder();

	sb.append("JavaSecureRandomEntropySource[blksize=" + BLOCK_SIZE);
       
	int i;
	for(i = 0; i < DEFAULT_SOURCES; i++) {
	    sb.append(", SecureRandom " + (i+1) + " provider=" +
		      sources[i].getProvider().toString());
	}
	sb.append("]");
	
	return sb.toString();
    }

    /**
     * Dispose of this entropy source, if we are done with it.
     * After this has been called, all attempts to get entropy will fail.
     */
    public void dispose() {
	sources = null;
	passedSelfTest = false;
	savedSelfTestEntropy = null;
	return;
    }

    /**
     * Get requested entropy.  This method returns the entropy as a byte
     * array.  It gets the entropy by reading from multiple Java
     * SecureRandom instances.  Note that this call
     * may block until entropy is available, because it uses the
     * SecureRandom generateSeed() method.
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
			     int maxOutputBytes)
    {
	byte[] ret;
	int blocks, tot, cc, bytes;

	// check that we haven't been disposed of
	if (sources == null) return null;

	// calculate number of blocks needed
	blocks = (int) Math.ceil((double) requestedEntropyBits
				 / (double) BITS_ENTROPY_PER_BLOCK);
	// adjust up to caller's requested minimum
	while (minOutputBytes > (blocks * BLOCK_SIZE)) { blocks++; }

	// check to make sure we don't exceed caller-supplied maximum
	if (maxOutputBytes != 0 && (blocks * BLOCK_SIZE) > maxOutputBytes) {
	    return null;
	}
	
	byte [] block = new byte[BLOCK_SIZE];
	bytes = blocks * BLOCK_SIZE;
	ret = new byte[bytes];
	
	int i;
	tot = 0;
	for(i = 0; i < blocks; i++) {
	    if (!fillBlock(block)) {
		return null;
	    }
	    else {
		System.arraycopy(block, 0, ret, tot, BLOCK_SIZE);
		tot += BLOCK_SIZE;
	    }
	}

	return ret;
    }    
  
    /**
     * Fill a block buffer by calling each SecureRandom in turn.
     * Return false if anything goes wrong, true on success.
     *
     * @param block a byte buffer of size BLOCK_SIZE
     * @return true on success
     */
    private boolean fillBlock(byte [] block) {
	int bytesPer;
	int k, px;
	byte [] seedbytes;

	bytesPer = BLOCK_SIZE / DEFAULT_SOURCES;
	px = 0;

	for(k = 0; k < DEFAULT_SOURCES; k++) {
	    seedbytes = sources[k].generateSeed(bytesPer);
	    if (seedbytes == null) return false;
	    System.arraycopy(seedbytes, 0, block, px, bytesPer);
	    px += bytesPer;
	}
	return true;
    }


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
	ret = getEntropy(128, BLOCK_SIZE, BLOCK_SIZE*2);
	if (ret.length != BLOCK_SIZE) {
	    return false;
	}
	if (!EntropyUtil.checkByteEntropy(ret, ret.length, 3.5)) {
	    return false;
	}

	savedSelfTestEntropy = ret;

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


    private static final int TEST_SIZES[] = { 128, 384 };

    /**
     * Simple unit test main method, 
     * simply creates an instance and calls
     * performSelfTest().  Then it calls getEntropy
     * and prints the output.  If there is a command-line
     * argument, then additional self-test will be
     * performed.
     */
    public static void main(String[] args) {
	JavaSecRandEntropySource rsrc;
	int i;
	byte [] output;
	double h;
		
	if (args.length > 0) {
	    System.err.println("Non-empty list of command-line args supplied.");
	    System.err.println("Setting up additional self-test.");
	}

	try {
	    System.err.println("About to call self-test method.");
	    rsrc = new JavaSecRandEntropySource();
	    if (rsrc.performSelfTest()) {
		System.err.println("Self-Test Passed!");
	    }
	    else {
		System.err.println("Self-test failed.");
		System.exit(1);
	    }
	} catch (Exception ie2) {
	    System.err.println("Error creating random source: " + ie2);
	    ie2.printStackTrace();
	}

		
	try {
	    rsrc = new JavaSecRandEntropySource();
	    for(i = 0; i < TEST_SIZES.length; i++) {
		output = rsrc.getEntropy(TEST_SIZES[i], TEST_SIZES[i]/8, 0);
		System.err.println("Test at size " + TEST_SIZES[i] + " returns array of " +
				   output.length + " bytes.");
		h = EntropyUtil.computeByteEntropy(output, output.length);
		System.err.println("    byte entropy = " + h + " bits");
	    }
	    rsrc.dispose();
	}
	catch(Exception ie) {
	    System.err.println("Error creating random source: " + ie);
	    ie.printStackTrace();
	}
		

    }

}
