package gov.nsa.ia.pass;

import gov.nsa.ia.drbg.*;
import gov.nsa.ia.util.*;

import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class manages creation and maintenance of the
 * DRBGs and EntropySource objects necessary for
 * generating cryptographic keys, passwords, and passphrases.
 * 
 * In addition to managing the entropy sources, this
 * class also has the ability to, at startup, read
 * extra entropy from a file, and at shutdown to
 * save entropy to a file, if configured by its
 * caller to do so.  
 * 
 * This class manages three types of entropy sources.
 * <ol>
 * <li>The primary entropy source is used as the source
 * for a HashDRBG.  This must be an really solid source
 * that generates very high entropy-per-byte, can be
 * called repeatedly, and blocks until it has high
 * quality entropy to deliver.  Normally this would be
 * a UnixDevRandomEntropySource on Linux.</li>
 * <li>A supplemental entropy source is used for 
 * additional input for one generation call
 * per regrab interval (normally 1 minute).  It
 * must be callable repeatedly, but does not need
 * to deliver high entropy-per-byte.  This is
 * optional but recommended</li>
 * <li>A startup entropy source is used for the
 * nonce value for HashDRBG instantiation, and is
 * also used to save some high-quality entropy from
 * the HashDRBG at shutdown.  This should be
 * a FileEntropySource; it must be callable once
 * at startup (getEntropy method) and once at 
 * shutdown (saveEntropy method).
 * </ol>
 * 
 * The usual calling sequence for this class would be:
 * create object, create sources, set sources, set logger,
 * call initialize method, call performSelfTest method,
 * call generateKey method many times, call shutdown method.
 * Also, it is often a good idea to set up a ShutdownHook
 * to call the shutdown method, by using Runtime.addShutdownHook
 * and the utility method getKeyGenerationShutdownHook().
 * 
 * @author nziring
 */
public class RandManager implements SelfTestable {
    /**
     * Number of blocks of good entropy to save to a file
     * at shutdown, if possible.  Block size is 8 bytes.
     */
    public static final int SAVE_BLOCKS = 16;
	
    /**
     * Basic strength to request for the DRBG, not a good idea
     * to override this, so this class provides no
     * way to do so.  This uses the maximum recommended
     * hash size of the DRBG under the NSAS: SHA-384.
     */
    public static final int DRBG_STRENGTH = 192;
	
    /**
     * Amount of entropy we can reasonably expect from 
     * the supplemental source, per call, in bits.
     */
    public static final int SUPPLEMENT_ENTROPY = 128;
	
    /**
     * Max amount of entropy we can unreasonably expect from the
     * startup source, per call, in bits.  (Remember, we believe
     * the startup source is extremely high-quality flat random
     * bits, so 512 bits of entropy from it should require only
     * 64 bytes of data.)
     */
    public static final int STARTUP_SOURCE_ENTROPY = 512;

    /**
     * Set to true if primary source self-test entropy may
     * be added to the nonce given to the instantiate function
     * of the DRBG.  
     * 
     * POST-REVIEW NOTE: Default value is false because SP800-90A
     * 11.3.2 can be construed as prohibiting re-use of self-test
     * entropy in any form.  Which is a darn shame since it is
     * perfectly good entropy.  (My own opinion is that the words
     * in 11.3.2 were intended to prohibit re-use of self-test
     * entropy as the primary entropy input, rather than as part
     * of the nonce.  Oh well.)
     */
    public static final boolean USE_EXTRA_SELFTEST_ENTROPY = false;


    private EntropySource primarySource;
    private EntropySource suppSource;
    private FileEntropySource startupSource;
    private HashDRBG rbg;
    private boolean okay;
    private String name;
    private Logger log;
    private long lastSupplementTime;
	
    /**
     * Constructor - create a KeyGenerationManager object.
     * The object will not yet be usable.  At the least, 
     * you must call setPrimarySource() to supply a usable
     * primary EntropySource and initialize() to fire up
     * the DRBG and perform successful self-test.
     * 
     * @param nam Base name for this manager, must be non-null
     * @param l Logger to use; if null, then a new Logger will be created
     */
    public RandManager(String nam, Logger l) {
	primarySource = null;
	suppSource = null;
	startupSource = null;
	okay = false;
	if (nam == null) throw new IllegalArgumentException("Non-null Name must be supplied.");
	name = nam;
	setLogger(l);
	log.fine("Initialized RandManager object, name=" + name);
    }
	
	
    /**
     * Return our Logger, in case caller needs to set something
     * on it or log some messages.  This will always return
     * a non-null, usable Logger.
     */
    public  Logger getLogger() {
	return log;
    }
	
    /** 
     * Set a new Logger for us.  This must be done BEFORE
     * calling initialize(), or it will be useless.  If
     * this is called with null, it will cause a new default
     * Logger to be created, but thats not usually a good idea.
     * 
     * @param l Logger to use for logging our operations
     */
    public  void setLogger(Logger l) {
	if (l != null) {
	    log = l;
	} else {
	    log = Logger.getLogger(name + "-log");
	    log.setLevel(Level.FINE);
	}
	if (rbg != null) {
	    rbg.setLogger(log);
	}
    }

    /**
     * Perform a shutdown of this RandManager.
     * This may only be called once, after which this
     * object is not usable.  This method has three jobs:
     * (1) save entropy to the startupSource if set, and
     * (2) call uninstantiate on our DRBG, and
     * (3) call dispose on all our entropy sources.
     */
    public  void shutdown() {
	// step 1
	if (okay && (rbg != null) && (startupSource != null)) {
	    try {
		if (startupSource.saveEntropy(rbg, SAVE_BLOCKS)) {
		    log.info("In RandManager " + name + " shutdown, saved entropy to " +
			     startupSource.getDestination());
		} else {
		    log.warning("In RandManager " + name + ", attempt to save entropy failed.");
		}
	    } catch(IOException ie) {
		log.warning("Saving entropy to file failed: " + ie);
	    }
	} else {
	    log.warning("In shutdown, unable to save entropy to file.");
	}
		
	// step 2
	if (rbg != null && rbg.isOkay()) {
	    rbg.uninstantiate();
	    rbg = null;
	}
	okay = false;
		
	// step 3
	if (primarySource != null) {
	    primarySource.dispose();
	    primarySource = null;
	}
	if (suppSource != null) {
	    suppSource.dispose();
	    suppSource = null;
	}		
	if (startupSource != null) {
	    startupSource.dispose();
	    startupSource = null;
	}
		
	log.info("Shut down RandManager " + name);
	return;
    }
	
    /**
     * Set the primary entropy source.  This source must
     * be callable repeatedly, and must block until it has
     * high-quality entropy to deliver.  This method
     * must be called before calling initialize(). 
     * If a primary source was
     * already set, that source will have its dispose()
     * method called prior to being replaced.
     * 
     * @param src A good EntropySource, such as a UnixDevRandomEntropySource or JavaSecRandEntropySource.
     */
    public  void setPrimarySource(EntropySource src) {
	if (src == null) {
	    throw new IllegalArgumentException("Primary entropy source must be non-null.");
	}
	if (src == primarySource) return; // No-op
		
	if (primarySource != null) {
	    primarySource.dispose();
	}
	primarySource = src;
	log.info("Set RandManager " + name + " primary entropy source to " + src);
	return;
    }

    /**
     * Set the supplementary entropy source.  This source must
     * be callable repeatedly.  This method
     * should be called before initialize(), but
     * may be called again later to set a different
     * supplemental source if desired.  If a supplemental source
     * is already set, that source will have its dispose()
     * method called prior to being replaced.  It is okay to
     * not set a supplemental source.
     * 
     * @param src An EntropySource, such as a FileEntropySource.
     */
    public  void setSupplementalSource(EntropySource src) {
	if (src == suppSource) return;	
	if (suppSource != null) {
	    suppSource.dispose();
	}
	suppSource = src;
	if (src != null) {
	    log.info("Set RandManager " + name + " supplemental entropy source to " + src);
	} else {
	    log.info("Set RandManager " + name + " supplemental entropy source to none.");
	}
	return;
    }
	
    /**
     * Set the startup entropy source.  This source must
     * be a FileEntropySource.  This method
     * should be called before initialize().
     * 
     * @param src A FileEntropySource that can support saveEntropy()
     */
    public  void setStartupSource(FileEntropySource src) {
	if (src == startupSource) return;	
	if (startupSource != null) {
	    startupSource.dispose();
	}
	startupSource = src;
	if (src != null) {
	    log.info("Set RandManager " + name + " start/save entropy source to " + src);
	} else {
	    log.info("Set RandManager " + name + " start/save entropy source to none.");
	}
	return;
    }
	
    /**
     * Return true if this RandManager is in a usable state.
     */
    public  boolean isOkay() {
	return okay && (rbg != null) && (rbg.isOkay());
    }
	
    /**
     * Initialize this RandManager object.  This method should
     * be called exactly once, before this RandManager can be
     * used.  If initialization succeeds, this method returns true
     * and the method isOkay() will return true also.  
     * 
     * Internally, this method uses the primarySource and the startupSource.
     * It builds the SP800-90 nonce from the startupSource and self-test
     * entropy from the primarySource.
     * 
     * @return true if initialization succeeds, false otherwise
     */
    public  boolean initialize() {
	byte[] nonce = null;
	byte[] testEntropy = null;
	int status;
		
	if (isOkay()) return true;
		
	// check pre-conditions
	if (primarySource == null) {
	    log.warning("Could not initialize RandManager " + name + " because no primary source has been set.");
	    return false;
	}
		
	// attempt to grab DRBG nonce from startupSource if possible, or system time otherwise
	if (startupSource != null) {
	    nonce = startupSource.getEntropy(STARTUP_SOURCE_ENTROPY, 8, 256);
	    if (nonce != null && nonce.length > 0) {
		log.fine("Got startup entropy nonce from " + startupSource.getDestination() + ", " +
			 nonce.length + " bytes.");
	    }
	}
	if (nonce == null) {
	    nonce = (System.currentTimeMillis() + "x").getBytes();
	    log.fine("Got startup entropy nonce from system time.");
	}
		
	// append self-test entropy from the primary source to the nonce, 
	// if allowed.
	// POST-REVIEW NOTE: this is prohibited by default, see above.
	//
	if (USE_EXTRA_SELFTEST_ENTROPY) {
	    testEntropy = primarySource.getSelfTestEntropy();
	    if (testEntropy != null && testEntropy.length > 0) {
		log.fine("Got additional startup nonce entropy from primary source self-test, "
			 + testEntropy.length + " bytes.");
		byte [] newnonce = new byte[nonce.length + testEntropy.length];
		System.arraycopy(nonce, 0, newnonce, 0, nonce.length);
		System.arraycopy(testEntropy, 0, newnonce, 0, testEntropy.length);
		nonce = newnonce;
	    }
	}
		
	// create the DRBG and instantiate it, this will cause the
	// DRBG to invoke the self-test of the primary source.
	rbg = new HashDRBG(name + "-drbg", primarySource);
	rbg.setLogger(log);
	status = rbg.instantiate(DRBG_STRENGTH, false, name, nonce);
	if (status == DRBGConstants.STATUS_SUCCESS) {
	    log.info("RandManager " + name + " successfully instantiated DRBG: " + rbg);
	} else {
	    log.severe("Instantiation of RandManager DRBG failed.  Cannot generate keys in " + name);
	    return false;
	}
		
	// all done!
	okay = true;
	return okay;
    }
	
	
    /**
     * Return the current DRBG.  Returns null if
     * this RandManager is not okay.
     *
     * Note that the caller should NOT uninstantiate the returned
     * DRBG.  The correct thing to do is to call shutdown on this
     * RandManager when all use of the DRBG is done.
     *
     * @return a HashDRBG, already instantiated, or null
     */
    public AbstractDRBG getDRBG() {
	if (!isOkay()) return null;

	return rbg;
    }

    
    /**
     * Generate a key of a specified size and return it.
     * If we cannot generate a key, return null.  This
     * method uses the generate() method of the DRBG.
     * If the time since the most recent use of the
     * supplemental source was more than the supplement
     * interval, then we grab some additional input from
     * the supplemental source and use it with the call
     * to the DRBG generate method.
     * 
     * @param numBytes size of the desired random key in bytes, more than 0
     */
    public  byte[] generateKey(int numBytes) {
	byte [] ret = null;
	byte [] addlInput = null;
	int status;
		
	// check that is generator is okay
	if (!isOkay()) {
	    log.warning("Attempt to call RandManager " + name + " generation when not okay!");
	    return null;
	}
		
	// validate that the value of numBytes is positive
	if (numBytes <= 0) {
	    log.warning("Attempt to call RandManager " + name +
			" generation with size 0 or negative.  Null returned.");
	    return null;
	}
		
	// validate that the value of numBytes is not larger than the 
	// instantiated DBRG strength
	if (numBytes > (rbg.getStrength() / 8)) {
	    log.warning("Attempt to call RandManager " + name + 
			" generation for+size " + numBytes + " which is greater than " +
			" available DRBG strength.  Null returned.");
	    return null;
	}
		
	// perform generation
	ret = new byte[numBytes];
	log.fine("RandManager " + name + " about to call DRBG generate for " + numBytes + " bytes.");
	status = rbg.generate(numBytes, 0, false, addlInput, ret);
	if (status == DRBGConstants.STATUS_SUCCESS) {
	    log.fine("RandManager " + name + " generated key of bytes " + ret.length);
	} else {
	    log.severe("RandManager " + name + " key generation failed!");
	    ret = null;
	}
		
	// all done
	return ret;
    }
	
	
    private static final int SELF_TEST_SIZES[] = { 16, 32 };

    /**
     * Perform a basic Known Answer test of our underlying DRBG.
     * This calls the static method on the HashDRBG class, and simply
     * returns the result, true or false.  This should be performed, and
     * should pass, before you call initialize().  
     *
     * @return true if HashDRBG known answer self-test passed
     */
    public boolean performDRBGKATest() {
	boolean result = HashDRBG.performKnownAnswerTests(getLogger());
	return result;
    }
	


    /**
     * Perform a self-test on a properly initialized RandManager object.
     * This tests generation of keys of sizes SELF_TEST_SIZES. All the test
     * generations must succeed in order for self-test to pass. On pass, this
     * method returns true.
     */
    public boolean performSelfTest() {
	if (!isOkay()) {
	    log.info("Self-test failing due to generator state not okay.");
	    return false;
	}

	log.fine("About to perform self-test on HashDRBG class.");
	HashDRBG trbg;
	trbg = new HashDRBG("self-test", new LousyEntropySource());
	trbg.setLogger(log);
	if (!trbg.performSelfTest()) {
	    log.warning("HashDRBG class failed self-test.  Failing RandManager self-test.");
	    return false;
	}

	log.info("Self-test of HashDRBG class succeeded, continuing to self-test of RandManager "
		 + name);
	byte[] keyval;
	int siz, i;
	for (i = 0; i < SELF_TEST_SIZES.length; i++) {
	    siz = SELF_TEST_SIZES[i];
	    log.fine("Self-test generating a raw key at size " + siz);
	    keyval = generateKey(siz);
	    if ((8*siz) <= rbg.getStrength()) {
		if (keyval == null) {
		    log.warning("Self-test failing at key size " + siz
				+ ", generateKey returned null.");
		    return false;
		}
		if (keyval.length != siz) {
		    log.warning("Self-test failing at key size " + siz
				+ ", generateKey returned wrong size.");
		    return false;
		}
	    } else {
		if (keyval != null) {
		    log.warning("Self-test failing, generateKey returned a value for size " + siz +
				" when the size was actually greater than available DRBG strength.");
		    return false;
		}
	    }
	    log.fine("Self-test for size " + siz + " succeeded.");
	}

	return true;
    }


    // TESTING
    
    protected static final int TEST_KEY_COUNT = 10;
    protected static final int TEST_KEY_SIZE = 32;
	
    /**
     * @param args
     */
    public static void main(String[] args) {
	String suppFile = null;
	String saveFile;
	RandManager kgm;
	EntropySource primarysrc;
	FileEntropySource startupsrc;
	FileEntropySource suppsrc = null;
		
	if (args.length == 0) {
	    System.err.println("Usage: java gov.nsa.ia.RandManager startup-file [suppl-file]");
	    System.exit(0);
	}
		
	saveFile = args[0];
	if (args.length > 1) suppFile = args[1];
		
	try {
	    kgm = new RandManager("UnitTestKGM", Logger.getLogger("RandManTest"));
	    kgm.getLogger().setLevel(Level.FINE);
	    primarysrc = new JavaSecRandEntropySource();
	    // primarysrc = new UnixDevRandomEntropySource();
	    startupsrc = new FileEntropySource(saveFile, 8, 2);
	    if (suppFile != null) suppsrc = new FileEntropySource(suppFile, 8, 2);
	    System.err.println("Created sources: p=" + primarysrc + ", s=" + startupsrc + ", s=" + suppsrc);
	    kgm.setPrimarySource(primarysrc);
	    kgm.setStartupSource(startupsrc);
	    kgm.setSupplementalSource(suppsrc);
	    System.err.println("About to initialize, might take time..");
	    if (kgm.initialize()) {
		System.err.println("KGM initialization succeeeded, proceeded to self-test, this might take a while if the DRBG blocks.");
		if (kgm.performSelfTest()) {
		    System.err.println("KGM self-test passed!");
		} else {
		    System.err.println("KGM self-test failed.  Bummer!");
		}
				
		// now try to get some test keys using the DRBG
		int ki;
		byte [] testkey;
		kgm.getLogger().setLevel(Level.INFO);
		for(ki = 0; ki < TEST_KEY_COUNT; ki++) {
		    testkey = kgm.generateKey(TEST_KEY_SIZE);
		    if (testkey == null || testkey.length != TEST_KEY_SIZE) {
			System.err.println("Key generate failed on bulk test iteration " + ki);
			System.exit(1);
		    }
		    // possibly print some of the keys here
		    System.err.println("Bulk test iteration no. " + ki + " key is " + EntropyUtil.bufferToString(testkey));
		    System.err.println("\tentropy is " + EntropyUtil.computeByteEntropy(testkey, TEST_KEY_SIZE));

		}
				
		System.err.println("Performing KGM shutdown.");
		kgm.shutdown();
	    } else {
		System.err.println("KGM initialization failed!");
	    }	
	} catch (Exception e) {
	    System.err.println("Error on unit test: " + e);
	    e.printStackTrace();
	}

    }

}
