package gov.nsa.ia.drbg;

import gov.nsa.ia.util.SelfTestable;

import java.util.logging.Logger;

/**
 * This abstract base class provides some basic support
 * functionality for DRBGs, including logging support and
 * management of a primary entropy source.  
 * Note that DRBGs that extend this class should attempt
 * to be thread-safe, but may stipulate that they are
 * not by returning false for the isThreadSafe() method.
 * 
 * @author nziring
 */

public abstract class AbstractDRBG implements DRBG, DRBGConstants, SelfTestable {
	/**
	 * The name of this DRBG.  This serves a role like that of the StateHandle in
	 * SP800-90.  It is also used for logging.
	 */
	protected String name;
	
	/** 
	 * true if the DRBG has been 
	 * instantiated and has not yet been uninstantiated and has
	 * not suffered a catastrophic_error.
	 */
	protected boolean instantiated;
	
	/**
	 * true iff the DRBG has suffered a catastrophic_error.
	 */
	protected boolean failed; 
	
	/** 
	 * true if the instantiate call requested prediction resistance
	 */
	protected boolean predResist;
	
	/**
	 * The primary entropy source that this DRBG uses to get more
	 * entropy during instantiation and reseeds.
	 */
	protected EntropySource source;
	
	/**
	 * Bit strength requested at instantiation (normally half the size of the
	 * underlying construction)
	 */
	protected int baseStrength;

	/**
	 * Number of requests satisfied generated since last reseed or entropy addition
	 */
	private long reseedCounter;
	
	/**
	 * Max number of bytes allowed to be output before reseed 
	 * will be required.  This must be set by subclasses.  The
	 * default is taken from SP800-90 section 10.1
	 */
	protected long maxRequestsAllowedBetweenReseeds = (1L << 48);
	
	/**
	 * Logger to be used for logging messages.  If this is null
	 * then no messages will be logged.  
	 * 
	 * @see java.util.logging.Logger
	 */
	protected Logger log;
	
	/**
	 * Base class constructor for a DRBG.  This accepts a handle,
	 * which is simply a name, and a
	 * necessary entropy source.  Neither of
	 * the arguments which may be null.
	 * 
	 * @param handle the name of this DRBG instance
	 * @param s  the EntropySource for this DRBG instance
	 */
	public AbstractDRBG(String handle, EntropySource s) {
		instantiated = false;
		failed = false;
		predResist = false;
		baseStrength = 0;
		name = handle;
		replaceEntropySource(s);
		reseedCounter = 0L;
	}
	
	/**
	 * Check whether this DRBG is usable at the moment.  This method
	 * is not mandated by SP800-90.
	 * 
	 * @return true if the DRBG is properly instantiated and usable (non-failed)
	 */
	public synchronized boolean isOkay() {
		return instantiated && !failed;
	}
	
	/**
	 * Check usable status of this DRBG.  This method is not mandated by
	 * SP800-90, but it may be useful.
	 *
	 * Get the instantiation bit strength of this DRBG.
	 * This will be the value passed to the instantiate() method, or
	 * 0 if the DRBG is not instantiated.
	 */
	public synchronized int getStrength() {
		if (!instantiated || failed) return 0;
		return baseStrength;
	}
	
	/**
	 * Return the value of the reseedCounter
	 */
	protected synchronized long getReseedCounter() {
		return reseedCounter;
	}
	
	/**
	 * Increment the number of requests since last reseed.
	 */
	protected synchronized void incrReseedCounter() {
		reseedCounter += 1;
	}
	
	/**
	 * Reset the number of requests since reseed.  This should
	 * be called only at reseed or instantiate.  Due to oddity of
	 * SP800-90, we reset to 1 not 0.
	 */
	protected synchronized void resetReseedCounter() {
		reseedCounter = 1;
	}
	
	/**
	 * Return false if the DRBG is not explicitly implemented to be 
	 * thread-safe (i.e. it can be invoked concurrently from
	 * multiple threads and will still work properly.  There
	 * are several ways to implement thread-safety in Java,
	 * and this abstract class does not force implementors to
	 * choose a particular one.  This basic implementation always
	 * returns false.
	 * 
	 * @return false, by default implementations are assumed not be thread-safe
	 */
	public boolean isThreadSafe() {
		return false;
	}
	
	/**
	 * Check whether reseed is needed prior to output.
	 * This returns true if prediction resistance was requested
	 * and supported at instantiation or if doing another generate would exceed
	 * the maximum allowed requests between reseeds.
	 * This should always be called prior to generating
	 * output.  If the DRBG is not in a usable state this
	 * method always returns false.  This method should be
	 * called from subclass implementation of the generate
	 * method.
	 * 
	 * @param numBytesRequested number of bytes about to be output
	 * @param predResistRequested whether this request needs prediction resistance
	 * 
	 * @return true if a reseed is required, false otherwise
	 */
	protected synchronized boolean reseedRequired(boolean predResistRequested) {
		if (!isOkay()) return false;
		
		if (predResist && predResistRequested) return true;
		if (reseedCounter + 1 > maxRequestsAllowedBetweenReseeds)
			return true;
		return false;
	}
	
	/**
	 * Set a new entropy source for this DRBG.  This would be used
	 * if the old entropy source were exhausted or no longer usable.
	 * The argument may not be null.
	 */
	public synchronized void replaceEntropySource(EntropySource s) {
		if (s == null) throw new IllegalArgumentException("EntropySource may not be null");
		
		source = s;
	}
	
    /**
     * Get a random byte from the DRBG.   This is a convenience wrapper
     * around generate().  If we cannot get bytes, then return null.
     *
     * @return random byte value (0-255) stored in an Integer, or null.
     */
    public Integer generateByte() {
	int status;
	int size_needed = 1;
	byte rand_bytes[];

	rand_bytes = new byte[size_needed];
	status = generate(size_needed, 32, false, null, rand_bytes);
	if (status != DRBGConstants.STATUS_SUCCESS) { return null; }

	 int ret = 0;
	 int i;
	 ret = rand_bytes[0] & 0x00ff;

	 //return new Integer(ret);
	 return Integer.valueOf(ret);
    }
	

    /**
     * Get a random integer at particular size from the DRBG, by getting numBytes
     * bytes and shifting them into an int.  Returns null if the DRBG failed
     * in any way.  This
     * method is not part of SP800-90, it is simply a convenience wrapper
     * around generate().
     *
     * @param requestedStrength strength parameter, if the DRBG cannot satisfy this then the call will fail.  Pass 0 to simply accept the instantiated strength of this DRBG
     * @param numBytes number of bytes to use for generating the integer, usually 2 or 3
     * @return random int stored in an Integer, or null on failure.
     */
    public Integer generateIntegerAtSize(int requestedStrength, int numBytes) {
	 int status;
	 int size_needed;
	 byte rand_bytes[];

	 if (numBytes < 1 || numBytes > 4) {
	     return null;
	 }

	 size_needed = numBytes;
	 rand_bytes = new byte[size_needed];
	 status = generate(size_needed, requestedStrength, false, null, rand_bytes);
	 if (status != DRBGConstants.STATUS_SUCCESS) { return null; }

	 int ret = 0;
	 int i;
	 for(i = 0; i < size_needed; i++) {
	     // bug fix, just ensure bits 31-8 of right hand operand are 0 
	     ret = (ret << 8) | (rand_bytes[i] & 0x00ff);
	 }

	 //return new Integer(ret);
	 return Integer.valueOf(ret);
    }


    /**
     * Get a random integer from the DRBG, by getting 4 bytes and shifting
     * them into an int.  Returns null if the DRBG failed in any way.  This
     * method is not part of SP800-90, it is simply a convenience wrapper
     * around generate().
     *
     * @param requestedStrength strength parameter, if the DRBG cannot satisfy this then the call will fail.  Pass 0 to simply accept the instantiated strength of this DRBG
     * @return random int stored in an Integer, or null on failure.
     */
    public Integer generateInteger(int requestedStrength) {
	 int status;
	 int size_needed;
	 byte rand_bytes[];
	 size_needed = 4;
	 rand_bytes = new byte[size_needed];
	 status = generate(size_needed, requestedStrength, false, null, rand_bytes);
	 if (status != DRBGConstants.STATUS_SUCCESS) { return null; }

	 int ret = 0;
	 int i;
	 for(i = 0; i < 4; i++) {
	     // bug fix, just ensure bits 31-8 of right hand operand are 0 
	     ret = (ret << 8) | (rand_bytes[i] & 0x00ff);
	 }

	 //return new Integer(ret);
	 return Integer.valueOf(ret);
    }


    	/**
	 * Return the name of this DRBG.
	 */
	public String getName() { return name; }
	
	/**
	 * Set a Logger to be used for logging messages about this
	 * DRBG.  If the Logger is null then no messages will be
	 * logged.  The caller should set the level using
	 * Logger.setLevel() before giving the logger to this
	 * DRBG. 
	 */
	public synchronized void setLogger(Logger l) {
		log = l;
		return;
	}
	
	/**
	 * Log a FINE level message if the Logger is set.
	 * Messages at this level should be used for debugging-style
	 * output.
	 */
	public synchronized void logDebug(String s) {
		if (log != null) {
			log.fine("DRBG " + name + ": " + s);
		}
	}	
	
	/**
	 * Log an INFO level message if the Logger is set.
	 * Messages at this level should be used for informational
	 * message output.
	 */
	public synchronized void logInfo(String s) {
		if (log != null) {
			log.info("DRBG " + name + ": " + s);
		}
	}
	
	/**
	 * Log an WARNING level message if the Logger is set.
	 * Messages at this level should be used for recoverable
	 * error output.
	 */
	public synchronized void logWarning(String s) {
		if (log != null) {
			log.info("DRBG " + name + ": " + s);
		}
	}	
	
	/**
	 * Log an SEVERE level message if the Logger is set.
	 * Messages at this level should be used for catastrophic
	 * error output.
	 */
	public synchronized void logSevere(String s) {
		if (log != null) {
			log.info("DRBG " + name + ": " + s);
		}
	}
	
        /**
	 * Utility function to convert a non-negative BigInteger
	 * to a byte array, but omit the leading 0 byte that
	 * the BigInteger's toByteArray() method prepends to hold
	 * the sign bit.  The output of this method can only be
	 * safely used for making a new BigInteger by using the
	 * 2-argument signum constructor, with a signum=1.
	 *
	 * Example: for the value 128, BigInteger's toByteArray()
	 * method would return { 0x00, 0x80 }, but this method will
	 * return { 0x80 }.
	 *
	 * @param bi a non-negative java.math.BigInteger
	 * @return byte array representation of the magnitude
	 */
        protected static final byte [] pbi2ba(java.math.BigInteger bi) {
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

	
}
