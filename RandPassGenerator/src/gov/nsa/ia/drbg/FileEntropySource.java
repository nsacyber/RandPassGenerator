package gov.nsa.ia.drbg;

import gov.nsa.ia.util.SelfTestable;

import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class 
 * support the Get_entropy_input function of SP800-90.
 * Implementations of this interface must deliver
 * entropy upon request, though a request may block
 * until enough entropy is available.
 * This particular class implements reading some
 * entropy from a file, and also writing a bunch
 * of entropy to a file.  It is used to save some
 * entropy from a running DRBG for use next time,
 * or for reading data with modest entropy from
 * the /proc filesystem files.
 */
public class FileEntropySource implements EntropySource, SelfTestable {
	/**
	 * File from which to read some entropy
	 */
    private File source;

    /**
     * default block size in bytes to read from 
     * the source.
     */
    protected int blockSize;

    /**
     * Expected bits of entropy available from RANDOM_SOURCE
     * per block of bytes obtained.
     */
    protected int entropyBitsPerBlock;
    
    /**
     * File into which to save entropy, if different from file from
     * which we read entropy.
     */
    private File destination;

    /**
	 * Create this EntropySource object for reading from a given file.
	 * 
	 * @param filename
	 *            path to the file to read bits from
	 * @param blksiz
	 *            number of bytes per block to be read from file
	 * @param bitsEntPerBlk
	 *            number of bits of entropy expected from each block
	 */
	public FileEntropySource(String filename, int blksiz, int bitsEntPerBlk) {
		if (filename == null) {
			throw new IllegalArgumentException("Null file name");
		}
		if (blksiz <= 0) {
			throw new IllegalArgumentException("Block size too small");
		}
		if (bitsEntPerBlk < 1 || bitsEntPerBlk > (blksiz * 8)) {
			throw new IllegalArgumentException("Invalid entropy expectation");
		}

		source = new File(filename);
		destination = source;
		blockSize = blksiz;
		entropyBitsPerBlock = bitsEntPerBlk;
	}
 
    /**
	 * Return a good string representation of this entropy source, for debugging
	 */
    public String toString() {
    	StringBuffer sb;
    	sb = new StringBuffer();
    	sb.append("FileEntropySource[src=");
    	sb.append(source.toString());
    	sb.append(",");
    	sb.append("dest=" + destination);
    	sb.append("]");
    	return sb.toString();
    }
    
    /**
     * Get the destination file name, if set.
     */
    public String getDestination() {
    	if (destination != null) 
    		return destination.toString();
    	else
    		return null;
    }
    
    /**
     * Set the destination File for saving entropy.  If set to null,
     * then saving entropy is explicitly disabled.
     */
    public void setDestination(String filename) {
    	if (filename == null) {
    		destination = null;
    	} else {
    		destination = new File(filename);
    	}
    	return;
    }

    /**
     * Get requested entropy.  This method returns the entropy as a byte
     * array.  It gets the entropy by reading from the give file.  It
     * may block until entropy is available.
     * Note that each time this is called we read the file anew.  
     * This works well for pseudo-files that deliver something
     * a little different each time, but is lousy for normal
     * files.
     * If the file cannot be read, then null is returned.  
     * This EntropySource uses the requestedEntropyBits to
     * compute how many blocks to read, but does not guarantee
     * to actually deliver that much entropy because it may
     * not be able to read that much data from the source.
     * 
     * @param requestedEntropy amount of entropy desired, in bits
     * @param minOutputBytes minimum amount of output caller will accept, in bytes, usually reqEntropy/8
     * @param maxOutputBytes this parameter is ignored in this implementation
     * 
     * @return byte array containing entropy (STATUS_SUCCESS) or null (STATUS_ERROR)
     */
    public byte[] getEntropy(int requestedEntropyBits, int minOutputBytes,
			int maxOutputBytes) {
		ByteArrayOutputStream baos;
		BufferedInputStream bis;
		byte[] buf;
		int blocks, total, tc, cc;
		blocks = ((int) Math.ceil(requestedEntropyBits
				/ (double) entropyBitsPerBlock));
		buf = new byte[blockSize];
		total = blocks * blockSize;
		if (total < minOutputBytes)
			total = minOutputBytes;
		baos = new ByteArrayOutputStream(blocks * blockSize);
		tc = 0;
		bis = null;
		
		if (minOutputBytes < (requestedEntropyBits / 8)) 
			return null;

		try {
			bis = new BufferedInputStream(new FileInputStream(source));
			for (tc = 0; tc < total; tc += cc) {
				cc = bis.read(buf);
				if (cc > 0)
					baos.write(buf, 0, cc);
				else
					break;
			}
		} catch (IOException ie1) {
		}
		if (bis != null)
			try {
				bis.close();
			} catch (IOException ie2) {
			}

		if (tc < minOutputBytes) {
			return null;
		} else {
			return baos.toByteArray();
		}
	}
    
    /**
     * Release any resources that we hold, currently none.
     */
    public void dispose() {
    	return;
    }
    
    /**
	 * This implementation of EntropySource does not support returning
	 * entropy gathered during self-test.  This method always returns null.
	 * 
	 * @return  null
	 */
	public byte[] getSelfTestEntropy() {
		return null;
	}

    /** 
     * Write entropy to the defined destination, reading that entropy
     * from an already-instantiated DRBG.  (Note that the destination
     * is, by default, the same as the source.  To set a different
     * destination, use setDestination.)
     *
     * @param rbg an instantiated, usable DRBG
     * @param blks how many of our configured blocks to copy
     * @return true if able to write to the file, false otherwise
     * @throws IOException if any file problems occur
     */
    public boolean saveEntropy(DRBG rbg, int blks) throws IOException {
		int total;
		int status;
		byte[] randbuf;
		int strength;
		boolean ret;

		ret = false;
		total = blks * blockSize;
		strength = rbg.getStrength();
		if (strength <= 0) {
			System.err.println("Strength <= 0, cannot save");
			return false;
		}

		if (destination == null) {
			// writing entropy disabled, return false
			System.err.println("destination is null, cannot save");
			return false;
		}

		randbuf = new byte[total];
		status = rbg.generate(total, rbg.getStrength(), false, null, randbuf);
		if (status == DRBGConstants.STATUS_SUCCESS) {
			FileOutputStream fos = null;
			fos = new FileOutputStream(destination);
			if (fos != null)
				try {
					BufferedOutputStream bos = new BufferedOutputStream(fos);
					bos.write(randbuf);
					bos.close();
					ret = true;
				} finally {
					try {
						fos.close();
					} catch (IOException ie3) { }
				}
		} 
		else {
			System.err.println("DRBG generate called failed, cannot save.");
		}

		return ret;
	}
    
    private String self_test_failure_msg = null;

    /**
     * Return the failure message from the performSelfTest method.
     * If the method hasn't been called, or the test succeeded, 
     * then this method returns null.
     */
    public String getSelfTestFailureMsg() {
	return self_test_failure_msg;
    }
    
    static final double SHORT_TEST_MIN_ENTROPY = 2.0;
    static final double LONG_TEST_MIN_ENTROPY = 2.5;
    
    /**
     * Perform a basic self-test on this entropy source.
     * This entails running calling the getEntropy method 
     * several times and checking that the correct behavior
     * occurs.  For those calls which generate entropy, we
     * do a simple byte-entropy computation and make sure it
     * exceeds a threshold.  This self-test is fairly complex
     * so you can call getSelfTestFailureMsg() to obtain
     * a value describing why the self-test failed.
     *
     * @return true on success, false on failure
     */
    public boolean performSelfTest() {
		byte[] ret;

		// case 1 - should return null
		ret = getEntropy(512, 6, 6);
		if (ret != null) {
		        self_test_failure_msg = "Call to getEntropy that should have failed due to bad parameters succeeded";
			return false;
		}

		// case 2 - should return a byte array of 32 bytes
		ret = getEntropy(256, ((256/8)/blockSize + 1) * blockSize, 0);
		if (ret == null) {
		        self_test_failure_msg = "Call to getEntropy that should have returned an array of 32 bytes returned null";
			return false;
		}
		if (!EntropyUtil.checkByteEntropy(ret, ret.length, SHORT_TEST_MIN_ENTROPY)) {
		        self_test_failure_msg = "entropy obtained from source failed short test entropy threshold";
			return false;
		}

		// case 2 - should return a byte array of 256 bytes
		ret = getEntropy(2048, 2048 / 8, 2048);
		if (ret == null) {
			self_test_failure_msg = "Call to getEntropy that should have returned an array of 256 bytes returned null";
			return false;
		}
		if (ret.length < 2048 / 8) {
			self_test_failure_msg = "Call to getEntropy that should have returned an array of 256 bytes returned fewer";
			return false;
		}
		if (!EntropyUtil.checkByteEntropy(ret, ret.length, LONG_TEST_MIN_ENTROPY)) {
			self_test_failure_msg = "entropy obtained from source failed long test entropy threshold";
			return false;
		}

		return true;
    }

    /**
     * Simple unit test main method, 
     * this main method expects one or more files to be specified
     * on the command-line.  Each file is treated as a test of the
     * FileEntropySource, but if more than one file is given then the
     * last file is treated specially, and is used for an output test.
     */
    public static void main(String [] args) {
    	FileEntropySource src;
    	int i;
    	int status;
    	boolean result;
    	
    	if (args.length < 1) {
    		System.err.println("Usage: java FileEntropySource infile1 infile2 ... outfile");
    	}
    	
    	for(i = 0; i < args.length; i++) {
    		if (i == 0 || i < (args.length - 1)) {
    			// input test
    			System.err.println("Creating FileEntropySource for " + args[i]);
    			src = new FileEntropySource(args[i], 16, 20); // wild guess at bitsEntPerBlk
    			System.err.println("Performing self-test..");
    			result = src.performSelfTest();
    			if (result) {
    				System.err.println("Self-test passed.");
    			} else {
			        System.err.println("Self-test failed, code=" + src.getSelfTestFailureMsg());
    			}
    		}
    		else {
    			// output test
    			System.err.println("About to perform output test on " + args[i]);

    			Logger log;
    			log = Logger.getLogger("DRBG-FileEntropySource-test");
    			log.setLevel(Level.FINE);
    			  			
    			EntropySource esrc = null;
    			HashDRBG rbg;
    			try {
    				log.info("Creating Unix /dev/random entropy source.");
					esrc = new UnixDevRandomEntropySource();
				} catch (IOException e) {
					System.err.println("Unable to create /dev/random entropy source for output test");
					e.printStackTrace();
					System.exit(1);
				}
				log.info("Created entropy source, now creating Hash DRBG using that source, could take time");
    			rbg = new HashDRBG("selftest-support", esrc);
    			rbg.setLogger(log);
    			status = rbg.instantiate(256, false, "file entropy source self-test", null);
    			if (status != DRBGConstants.STATUS_SUCCESS) {
    				System.err.println("Unable to create DRBG, good-bye.");
    				System.exit(2);
    			} else {
        			log.info("Created and instantiated DRBG okay");
    			}
    			System.err.println("Created necessary support DRBG (str=" + rbg.getStrength() + 
    					"), creating FileEntropySource for " + args[i]);
    			
    			src = new FileEntropySource(args[i], 16, 20);
    			System.err.println("About to attempt to get random from the DRBG and save some entropy...");
    			result = false;
    			try {
    				result = src.saveEntropy(rbg, 200);
    			} catch (IOException ie4) {
    				System.err.println("IO error on saving entropy: " + ie4);
    				ie4.printStackTrace();
    			}
    			if (result) {
    				System.err.println("done, saved 200 blocks to " + args[i]);
    			} else {
    				System.err.println("failed, unable to save entropy to " + args[i]);
    			}
    		}
    		
    	}
    	
    }

}
