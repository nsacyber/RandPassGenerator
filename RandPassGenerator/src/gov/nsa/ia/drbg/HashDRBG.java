package gov.nsa.ia.drbg;

import gov.nsa.ia.util.*;

import java.math.BigInteger;
import java.util.logging.*;
import java.util.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;


/**
 * This class implements the 'Hash' DRBG specification from
 * NIST SP800-90, section 10.  It uses the Hash class to do
 * its hashing, choosing a particular algorithm based on
 * the requested strength.  (Note that, as per SP800-57, the strength
 * is half the hash size.)
 * 
 * @author nziring
 */
public class HashDRBG extends AbstractDRBG {
	/**
	 * Absolute max supported strength this class will accept
	 */
        protected static final int MAX_STRENGTH = 256;
	
	/**
	 * Absolute min supported stength this class will accept
	 */
	protected static final int MIN_STRENGTH = 64;
	
	
	/**
	 * Seed/state length in bits; usually 440 or 888
	 */
	private int seedlen;
	
	/**
	 * Hash output size in bits; usually 160 or 256 bits, but might be larger
	 */
	private int hsize;
	
	/**
	 * Hash output size in bytes, hsize/8
	 */
	private int hlength;
	/**
	 * The SP800-90 state value V.
	 */
	private BigInteger v;
	
	/**
	 * The SP800-90 state value C.
	 */
	private BigInteger c;
	
	/**
	 * The modulus for doing big integer arithmetic
	 * with v and c.  This is 2^seedlen.
	 */
	private BigInteger modulus;
	
	/**
	 * Size of hash to use for various DRBG strengths, from SP800-57.
	 * Each value is a pair; the first element of the pair is a
	 * DRBG strength value, the second element is the size of hash
	 * function to use.
	 */
	private static final int[][] STRENGTH_TO_SIZE_MAP = {
		{ 80, 160 },
		{ 128, 256 },
		{ 192, 384 },
		{ 256, 512 }
	};
	
	
	/**
	 * Size of seedlen to use for various DRBG strengths, from SP800-90.
	 * Note that the values are in bits.
	 */
	private static final int[][] STRENGTH_TO_SEEDLEN_MAP = {
		{ 80, 440 },
		{ 128, 440 },
		{ 192, 888 },
		{ 256, 888 }
	};	
	
	/**
	 * The Hash object that will perform hashing for this DRBG.
	 */
	private Hash h;
	
        /**
	 * Minimum length of result we'll accept from a call to a source's
	 * getEntropy method, in bits; anything shorter causes a failure.
	 */
        private int minSeedEntropy;


        /**
	 * Basic constructor for the HashDRBG.  This method does
	 * very little, the instantiate() method must be called
	 * before the HashDRBG will be usable.
	 * 
	 * @param handle the name of this DRBG instance
	 * @param s the primary entropy source to be used
	 */
	public HashDRBG(String handle, EntropySource s) {
		super(handle, s);
		
		v = BigInteger.ZERO;
		c = BigInteger.ZERO;
		modulus = BigInteger.ZERO;
		h = null;
	}

	
	/**
	 * Generate some random bytes and return them, possibly reseeding if
	 * necessary.  If anything goes wrong, or this DRBG is not properly
	 * instantiated, or if the requested strength is greater than this DRBG
	 * can provide, then this method will fail and return no output.  Also,
	 * this method returns an error if the predictionResistance parameter is
	 * set but the DRBG instantiation did not request prediction resistance
	 * capabilities (odd behavior, but mandated by SP800-90).
	 * 
	 * @see gov.nsa.ia.drbg.DRBG
	 * @param numBytes number of bytes of output requested (SP800-90 output bits)
	 * @param requestedStrength desired bit strength of the output, 0 for default
	 * @param predictionResistance use pred resistance reseed for this request
	 * @param additionalInput additional bytes of input to use with reseed action
	 * @param output buffer for returned bytes, must be at least numBytes long
	 * @return STATUS_SUCCESS (0) on success, non-zero status otherwise
	 */
	public synchronized int generate(int numBytes, int requestedStrength,
			boolean predictionResistance, byte[] additionalInput, byte[] output) 
	{
		if (!instantiated) {
			logWarning("returning from generate with error because DRBG is not instantiated");
			return STATUS_ERROR;
		}
		if (failed) {
			logWarning("returning from generate with error because DRBG is in failed state");
			return STATUS_ERROR;
		}
		if (requestedStrength > getStrength()) {
			logWarning("returning from generate with error because requested strength cannot be satisfied");
			return STATUS_ERROR;
		}
		// the check below is stupid, but SP800-90 requires it
		if (predictionResistance && !predResist) {
			logWarning("returning from generate with error because prediction resistance requested and original instantiation did not specify support for it. (SP800-90 section 9.3)");
			return STATUS_ERROR;
		}
		logDebug("Generate proceeding for Hash DRBG " + getName() + ", requested bytes " + numBytes);
			
		int ret = STATUS_SUCCESS;		
		byte [] tmpbuf;
		
		// step 1
		if (reseedRequired(predictionResistance)) {
		    logDebug("reseed required based on time or prediction resistance");
			ret = this.reseed(additionalInput);
			if (ret != STATUS_SUCCESS) {
				logWarning("returning from generate with error because required reseed failed");
			}
		} 

		// step 2
		if (additionalInput != null && additionalInput.length > 0) {				
				if (h.reset() != STATUS_SUCCESS) {
					logWarning("returning from generate with error because hash reset failed");
					return STATUS_ERROR;
				}
				if (h.update((byte)0x02) != STATUS_SUCCESS ||
					h.update(pbi2ba(v)) != STATUS_SUCCESS ||
					h.update(additionalInput) != STATUS_SUCCESS) {
					logWarning("returning from generate with error because hashing failed");
					return STATUS_ERROR;					
				}
				tmpbuf = new byte[h.getDigestSize()];
				if (h.getDigest(tmpbuf) != STATUS_SUCCESS) {
					logWarning("returning from generate with error because hash output failed");
					return STATUS_ERROR;					
				}
				BigInteger w = new BigInteger(1, tmpbuf);
				w = w.add(v);
				v = w.mod(modulus);
		}

		// step 3 
		if (hashgen(numBytes, output) != STATUS_SUCCESS) {
			logWarning("returning from generate with error because generation failed");
			return STATUS_ERROR;					
		}
		
		// step 4
		if (h.reset() != STATUS_SUCCESS) {
			logWarning("returning from generate with error because hash reset failed");
			return STATUS_ERROR;
		}

		// step 5
		if (h.update((byte)0x03) != STATUS_SUCCESS ||
			h.update(pbi2ba(v)) != STATUS_SUCCESS) {
			logWarning("returning from generate with error because hashing failed");
			return STATUS_ERROR;					
		}
		tmpbuf = new byte[h.getDigestSize()];
		if (h.getDigest(tmpbuf) != STATUS_SUCCESS) {
			logWarning("returning from generate with error because hash output failed");
			return STATUS_ERROR;					
		}
		BigInteger hv = new BigInteger(1, tmpbuf);		
		
		v = v.add(hv).add(c).add(new BigInteger(getReseedCounter()+"")).mod(modulus);
		
		// step 6
		incrReseedCounter();
		
		logDebug("returning from generate with success, output is " + numBytes + " bytes.");
		
		return ret;
	}
	
	/**
	 * Implementation of Hashgen function from SP800-90 section 10.1.1.4
	 * @param numBytes number of output bytes requested
	 * @param output output buffer, must be at least numBytes long, at most numBytes bytes will be written into this buffer
	 * @return STATUS_SUCCESS if everything works
	 */
	protected int hashgen(int numBytes, byte [] output) {
		BigInteger data;
		int m, i;
		byte [] tmpbuf;
		ByteArrayOutputStream w;
		w = new ByteArrayOutputStream(numBytes);
		
		m = (int)Math.ceil((double)numBytes / h.getDigestSize());
		data = v.add(BigInteger.ZERO);

		tmpbuf = new byte[h.getDigestSize()];
		for(i = 0; i < m; i++) {
			if (h.reset() != STATUS_SUCCESS) return STATUS_ERROR;					
			byte [] databuf = pbi2ba(data);
			if (h.update(databuf) != STATUS_SUCCESS) return STATUS_ERROR;
			if (h.getDigest(tmpbuf) != STATUS_SUCCESS) return STATUS_ERROR;

			try { w.write(tmpbuf); } catch (IOException e) { return STATUS_ERROR; }
			data = data.add(BigInteger.ONE).mod(modulus);
		}
		System.arraycopy(w.toByteArray(), 0, output, 0, numBytes);		
		return STATUS_SUCCESS;
	}

	/**
	 * Implementation of the instantiation functionality
	 * from SP800-90 section 10.1.1.2.
	 * 
	 * @see gov.nsa.ia.drbg.DRBG
	 * @param requestedStrength desired strength in bits (usually 128, 160, or 256)
	 * @param predictionResistanceFlag whether ability to call with prediction resistance is required, usually false
	 * @param personalizationString  instance-specific string to feed into hash hopper
	 * @param nonce  additional bytes of entropy to feed into hash hopper, optional
	 */
	public synchronized int instantiate(int requestedStrength,
			boolean predictionResistanceFlag, String personalizationString,
			byte[] nonce)
        {
		if (instantiated) {
			logWarning("returning from instantiate with error because DRBG already instantiated");
			return STATUS_ERROR;
		}
		if (failed) {
			logWarning("returning from instantiate with error because DRBG is in failed state");
			return STATUS_ERROR;
		}
		
		if (requestedStrength > MAX_STRENGTH || requestedStrength < MIN_STRENGTH) {
			logSevere("Requested strength value " + requestedStrength + " bits not supported");
			failed = true;
			return STATUS_CATASTROPHIC_ERROR;
		}
		if (source == null) {
			logSevere("No valid entropy source supplied, cannot instantiate");
			return STATUS_CATASTROPHIC_ERROR;
		}

		/**
		 * POST-REVIEW NOTE: added entropy length checks for conformance
		 * with SP800-90.
		 */
		minSeedEntropy = requestedStrength;

		/**
		 * POST-REVIEW NOTE: need to log which entropy source
		 * we're using.  The entropy source toString method most
		 * provide relevant information.
		 */
		logInfo("Instantiating HashDRBG using source " + source);

		if (source.performSelfTest()) {
		        // POST-REVIEW NOTE: this message logs that the source
		        // passed self-test, and includes the Java crypto
		        // provider as part of the source if necessary.  See
		        // the toString() method of JavaSecureRandomEntropySource
			logInfo("DRBG instantiation, entropy source passed self-test: " + source);
		} else {
			logSevere("Entropy source failed self-test, instantiation fails");
			return STATUS_CATASTROPHIC_ERROR;
		}
		
		predResist = predictionResistanceFlag;
		seedlen = 0;
		
		int i;
		for(i = 0; i < STRENGTH_TO_SEEDLEN_MAP.length; i++) {
			if (STRENGTH_TO_SEEDLEN_MAP[i][0] >= requestedStrength) {
				seedlen = STRENGTH_TO_SEEDLEN_MAP[i][1];
				break;
			}
		}
		if (seedlen == 0) {
			logSevere("Unable to compute necessary seed length.  Fatal error.");
			failed = true;
			return STATUS_CATASTROPHIC_ERROR;
		} else {
			logInfo("HashDRBG instantiation seed length=" + seedlen);
		}
		hsize = 0; 
		for(i = 0; i < STRENGTH_TO_SIZE_MAP.length; i++) {
			if (STRENGTH_TO_SIZE_MAP[i][0] >= requestedStrength) {
				hsize = STRENGTH_TO_SIZE_MAP[i][1];
				// base strength is half the hash size
				baseStrength = hsize / 2;
				break;
			}
		}
		if (hsize == 0) {
			logSevere("Unable to compute necessary hash output length.  Fatal error.");
			failed = true;
			return STATUS_CATASTROPHIC_ERROR;
		}
		
		logInfo("Instantiation proceeding for Hash DRBG " + getName() + ", state size is " + seedlen);
		
		hlength = hsize/8;
		h = new Hash(hsize);
		if (h.performSelfTest()) {
			logInfo("Hash self-test for hash of size " + hsize + " passed during instantiation of Hash DRBG.");
		}
		else {
			logSevere("Hash self-test failed for hash of size " + hsize + " - fatal error.");
			failed = true;
			return STATUS_CATASTROPHIC_ERROR;
		}
		
		v = BigInteger.ONE;
		c = BigInteger.ONE;
		modulus = new BigInteger("2");
		modulus = modulus.pow(seedlen);
		
		ByteArrayOutputStream acc;
		acc = new ByteArrayOutputStream();
		byte [] ent;
		
		
		logInfo("About to request main entropy seed, " + seedlen + " bits");
		ent = source.getEntropy(seedlen, seedlen/8, 0);
		if (ent == null) {
			logSevere("Entropy source unable to deliver entropy during instantiation - fatal error");
			return STATUS_ERROR;
		}
		logInfo("Entropy source delivered some entropy in instantiate, length=" + (ent.length * 8) + " bits");
		
		
		// POST-REVIEW NOTE: check that the entropy buffer we received back is
		// at least as long as the minimum size (which SP800-90 specifies as the
		// strength value, see section 10.1)
		if ((ent.length * 8) < minSeedEntropy) {
		    logSevere("Entropy source delivered entropy buffer that is too short during instantiation - fatal error");
		    return STATUS_ERROR;
		}
		
		// Step 1 - seed_material = entropy_input || nonce || personalization_string
		try {
			acc.write(ent);
			if (nonce != null) acc.write(nonce);
			if (personalizationString != null) acc.write(personalizationString.getBytes());
		} catch (IOException e) {
			// this will never happen with ByteArrayOutputStream
			logSevere("Error preparing instantiation entropy buffer.");
			return STATUS_ERROR;
		}
		byte [] seedMatBytes;
		seedMatBytes = acc.toByteArray();

		// Step 2 - seed = Hash_df(seed_material, seedlen)
		byte [] hash = new byte[seedlen / 8];  // fixed!
		if (h.hash_df(seedMatBytes, seedlen, hash) != STATUS_SUCCESS) {
			logSevere("Error hashing entropy during instantiation");
			return STATUS_ERROR;
		}

		// Step 3 - V=seed
		v = new BigInteger(1, hash);
		
		// Step 4 - c=Hash_df( 0 | seed, seedlen )
		acc.reset();
		try {
			acc.write(0);
			acc.write(hash);
		} catch (IOException e4) {
			logSevere("Unable to build up input for hash");
		}
		if (h.reset() != STATUS_SUCCESS) {
			logSevere("Error resetting hash during instantiation");
			return STATUS_ERROR;
		}
		
		if (h.hash_df(acc.toByteArray(), seedlen, hash) != STATUS_SUCCESS) {
			logSevere("Error hashing seed during instantiation");
			return STATUS_ERROR;
		}
		
		c = new BigInteger(1, hash);
		
		// Step 5 - reseed counter = 0
		resetReseedCounter();
		logDebug("Finished instantiation successfully, usage counter is " + getReseedCounter() + " and limit is " + maxRequestsAllowedBetweenReseeds);

		// Done successfully!
		instantiated = true;
		return STATUS_SUCCESS;
	}

	
	/**
	 * Reseed this DRBG from its source, also adding the given additional
	 * entropy if supplied. 
	 * 
	 * @see gov.nsa.ia.drbg.DRBG#reseed(byte[])
	 */
	public synchronized int reseed(byte[] additionalInput) {
		if (!instantiated) {
			logWarning("returning from reseed with error because DRBG is not instantiated");
			return STATUS_ERROR;
		}
		if (failed) {
			logWarning("returning from reseed with error because DRBG is in failed state");
			return STATUS_ERROR;
		}
		
		logInfo("Reseed proceeding for Hash DRBG " + getName() + ", state size is " + seedlen);
		
		ByteArrayOutputStream acc;
		acc = new ByteArrayOutputStream();
		byte [] ent;
		
		ent = source.getEntropy(seedlen, seedlen/8, 0);
		if (ent == null) {
			logSevere("Entropy source unable to deliver entropy during reseed - fatal error");
			return STATUS_ERROR;
		} 
		logInfo("Entropy source delivered some entropy in reseed, length=" + (ent.length * 8) + " bits");

		// POST-REVIEW NOTE: check that the entropy buffer we received back is
		// at least as long as the minimum size (which SP800-90 specifies as the
		// strength value, see section 10.1)
		if ((ent.length * 8) < minSeedEntropy) {
		    logSevere("Entropy source delivered entropy buffer that is too short during instantiation - fatal error");
		    return STATUS_ERROR;
		}
		
		
		// Step 1 - seed_material = 01 | V | entropy_input | addl_input
		try {
			acc.write((byte)0x01);
			// acc.write(v.toByteArray());
			acc.write(pbi2ba(v));
			acc.write(ent);
			if (additionalInput != null && additionalInput.length > 0) {
				acc.write(additionalInput);
			}
		} catch (IOException e) {
			// this will never happen with ByteArrayOutputStream
			logSevere("Error preparing reseed entropy buffer.");
			return STATUS_ERROR;
		}
		
		// Step 2 - seed = Hash_df(seed_material, seedlen)
		byte [] hash = new byte[seedlen / 8]; // fixed!
		if (h.hash_df(acc.toByteArray(), seedlen, hash) != STATUS_SUCCESS) {
			logSevere("Error hashing entropy during reseed");
			return STATUS_ERROR;
		}

		// Step 3 - V=seed
		v = new BigInteger(1, hash);
		
		// Step 4 - c=Hash_df( 0 | seed, seedlen )
		acc.reset();
		try {
			acc.write(0);
			acc.write(hash);
		} catch (IOException e4) {
			logSevere("Unable to build up input for hash");
		}
		if (h.reset() != STATUS_SUCCESS) {
			logSevere("Error resetting hash during reseed");
			return STATUS_ERROR;
		}
		
		if (h.hash_df(acc.toByteArray(), seedlen, hash) != STATUS_SUCCESS) {
			logSevere("Error hashing seed during reseed");
			return STATUS_ERROR;
		}
		
		c = new BigInteger(1, hash);
		
		// Step 5 - reseed counter = 1
		resetReseedCounter();
		
		return STATUS_SUCCESS;
	}

	/**
	 * Uninstantiate this DRBG.  After this is called, the DRBG will not
	 * be usable, but can be re-instantiated.
	 * 
	 * @return STATUS_SUCCESS if uninstantiate could be completed, STATUS_ERROR if the drbg was in a failed or uninstantiated state already
	 */
	public synchronized int uninstantiate() {
		if (!instantiated) {
			logWarning("returning from uninstantiate with error because DRBG not instantiated");
			return STATUS_ERROR;
		}
		if (failed) {
			logWarning("returning from uninstantiate with error because DRBG is in failed state");
			return STATUS_ERROR;
		}		
		
		v = BigInteger.ZERO;
		c = BigInteger.ZERO;
		h = null;
		instantiated = false;
		return STATUS_SUCCESS;
	}

        static final int[] SELFTEST_STRENGTHS = { 64, 80, 80, 128, 192 };
	static final boolean [] SELFTEST_PREDS = { false, true, false, false, false };
	
	static final byte [] SELFTEST_NONCE = {
		(byte)67, (byte)44, (byte)120, (byte) 199, (byte)1, (byte)44, (byte)58, (byte)0, (byte)224, (byte)41, (byte)33, (byte)161, (byte)22, (byte)7
	};
	static final int [] SELFTEST_SIZES = { 8, 32, 10001 };
	
	/**
	 * Perform a fairly broad self-test of this Hash-based DRBG.  This
	 * self-test runs through a cycle of testing at several strengths.
	 * Each cycle involves:
	 * <ol>
	 * <li>instantiating the drbg at the requisite strength</li>
	 * <li>generate random output of several sizes (checking the output each time)</li>
	 * <li>reseed the drbg</li>
	 * <li>uninstantiate the drbg</li>
	 * </ol>
	 * 
	 * If this method returns true, then we can have excellent confidence that
	 * the DRBG code is working okay.  (The real quality of the random will still
	 * depend in part on the quality of the entropy source.)
	 */
	public synchronized boolean performSelfTest() {
		boolean ret = true;
		int status;
		int cycle, size;
		byte [] outbuf;
		int retries;
		
		testloop:
		for(cycle = 0; cycle < SELFTEST_STRENGTHS.length; cycle++) {
			logDebug("selftest in progress, cycle " + cycle + " strength=" + SELFTEST_STRENGTHS[cycle]);
			status = instantiate(SELFTEST_STRENGTHS[cycle],
									  SELFTEST_PREDS[cycle],
									  "selftest", SELFTEST_NONCE);
			if (status != STATUS_SUCCESS) { ret = false; break; }
			for(size = 0; size < SELFTEST_SIZES.length; size++) {
				
				// need multiple tries here, in case weird random value gets returned
				// which can happen with small probability
				for(retries = 0; retries < 3; retries++) {
					outbuf = new byte[SELFTEST_SIZES[size]]; // set to all zeros
					status = this.generate(SELFTEST_SIZES[size], SELFTEST_STRENGTHS[cycle],
										SELFTEST_PREDS[cycle], "foobar".getBytes(), outbuf);
					if (status != STATUS_SUCCESS) { ret = false; break testloop; }
					// make sure buffer isn't still all zeros and can pass simple chi-squared test
					if (!checkDRBGOutput(outbuf)) { 
						logWarning("Weird error during self-test, generate returned success but output buffer is fails simple checks.");
						if (retries > 1) {
							logWarning("Retries exhausted, failing self-test!");
							ret = false; 
							break testloop;
						}
					} else {
						// no need for retries, generated buffer was okay!
						break;
					}
				}
				
				
			}
			status = reseed(null);
			if (status != STATUS_SUCCESS) { ret = false; break; }
			status = uninstantiate();
			if (status != STATUS_SUCCESS) { ret = false; break; }
		}
		return ret;
	}



    /**
     * Initialize known-answer test data values, taken from the NIST-supplied 800-90A
     * test file Hash_DRBG.txt.  (For now this is manual, but it would be possible
     * to re-implement this into reading the Hash_DRBG.txt test vector file.
     * Returns a List of one or more HashDRBGKnownAnswerTest data objects, or null
     * on error.
     *
     * At the moment, the known answer tests defined here do not test all the
     * features of the SP800-90 Hash DRBG.  Need a bigger spectrum of tests to
     * test the AdditionalInput parameter for reseed, and the predictionResistance
     * flag and the personalizationString.
     *
     */
    private static List<HashDRBGKnownAnswerTest> initializeTests() {
	ArrayList<HashDRBGKnownAnswerTest> ret = new ArrayList<HashDRBGKnownAnswerTest>();

	// test 1 step 1 - from line 12744 of NIST Hash_DRBG.txt, test COUNT=0
	HashDRBGKnownAnswerTest hdkat;
	hdkat = new HashDRBGKnownAnswerTest(128);

	// test 1 step 2
	hdkat.setStep2("63363377e41e86468deb0ab4a8ed683f6a134e47e014c700454e81e95358a569",
		       "808aa38f2a72a62359915a9f8a04ca68",
		       "32ab605ddc8d5651093b8a59bd9d3adea1249e21a69e2e4a3967515fa03ad41ccf5b126eb9f3b268080c952df88241fe4cc27bbcbbbed5",
		       "8ea2691d1915ebb4975593ca3fbad0ba137026d901a95950a207c41dc7773e15c1e85f4a5f91002866830bebe5c4ee1785b839323fbb44");

	// test 1 step 3
	hdkat.setStep3("e62b8a8ee8f141b6980566e3bfe3c04903dad4ac2cdf9f2280010a6739bc83d3",
		       "59177d93843f0550f33933a51eb488168699ab9c85651536a61f7ec71e8b274a151f17e56becaf531dcfc955f2f1adb6536d51b256d53c",
		       "897c02699f4254e1f33c94f7bfa85da3826df6c2590ed0815cbced36d77aa3375a1582ffc1c887416afd1ba0f04b6ddff81a2b0e5b844d");

	// test 1 step 4
	hdkat.setStep4(1024,
		       "e2937ffd23815a32e675c89cde5ce5ba0907a25ede73e61c9ec76d67da582c94001fda32b60ec40202a164c6a4d66411cc6b99b1284617",
		       "897c02699f4254e1f33c94f7bfa85da3826df6c2590ed0815cbced36d77aa3375a1582ffc1c887416afd1ba0f04b6ddff81a2b0e5b844d");

	// test 1 step 5
	hdkat.setStep5(1024,
		       "6c0f8266c2c3af14d9b25d949e05435d8b7599213782b6eac6cd90a10d48e1c96088f5dba20241b68cb64bb05028c35e5558ef8a6edca6",
		       "897c02699f4254e1f33c94f7bfa85da3826df6c2590ed0815cbced36d77aa3375a1582ffc1c887416afd1ba0f04b6ddff81a2b0e5b844d",
		       "04eec63bb231df2c630a1afbe724949d005a587851e1aa795e477347c8b056621c18bddcdd8d99fc5fc2b92053d8cfacfb0bb8831205fad1ddd6c071318a6018f03b73f5ede4d4d071f9de03fd7aea105d9299b8af99aa075bdb4db9aa28c18d174b56ee2a014d098896ff2282c955a81969e069fa8ce007a180183a07dfae17");


	ret.add(hdkat);


	// test 2 step 1 - from line 19112 of NIST Hash_DRBG.txt, test COUNT=0
	hdkat = new HashDRBGKnownAnswerTest(192);

	// test 2 step 2
	hdkat.setStep2("2d3e072e78b3d5af2d60424b37a1ca56b24ad1b1fb27a9c327db0651cb75341c",
		       "147d214920513cd539ce383f810d9551",
		       "bd9fe59036c728dbe30392569dedd9cca0cfaf9e7be20745e28e3a86615149caf4d970062c59b8f0ae7235f5d52762820ce6443cd313289d1c84e1b0e12ee992435008dc32904ea28fad4abfa00ff54adfb7186cb4d335b54ceff76b1992ae1ee3997054e76f88108783744324df96",
		       "d2b4ad747db0dafd96edded2a41d9cb7e189cc727066da2d1253a6818ce97870cd3e07de9736eec58536a271e1955931e4bb7832604ea487c3fbb5f510c465e9985ef066d70631d4b98e77dae9b6397103d6564798a6320d9716a6826945687a3557be1132a1a23007c89c362a52c3"
		       );

	// test 2 step 3
	hdkat.setStep3("7597a56fdbaa0cb66cef235ccb6bbb423ef2a2f19e5a65a7b86dd11d0cee6cd4",
		       "fbcb667f386b611aadf6d76999427af0adeabae5b4b2898bf37a57554f6dbf0758b2095f4b4f06415c8a06f27773cf0f7e48b8c41eb5d7d4d48f628067c773f7ae0b9e24adaf4999b4330d73b0c9340f51b6e9e6f2e3f3d43fb8f4421349bc4e05c4e09202124b76c83b3ecf821f30",
		       "46c505af058b37dfd9f59932ac17048fb307ffc5c27195d8bacf5521f811c1f157ce7589258ef328a55f3aea70e4ab09880c59f55ea211681c18584465ce1732503d991566cb3651ddf5a59fbb3ac82399d358226e94204c1f5b712dbb7aa07f1868dcf0278edcc37708102bdd3b60"
		       );

	// test 2 step 4
	hdkat.setStep4(1536,
		       "42906c2e3df698fa87ec709c45597f8060f2baab77241f64ae49ac77477f80f8b0807ee870ddf96a01e941dce8587a19065512b97d57e93cf0a7bac4cd958c1ca086254c329645369fd5f46d3907eda0be1c1e1243fbf3a30fa70edda40b7e81c39ea329990dfc9a0c249fd3b4f93a",
		       "46c505af058b37dfd9f59932ac17048fb307ffc5c27195d8bacf5521f811c1f157ce7589258ef328a55f3aea70e4ab09880c59f55ea211681c18584465ce1732503d991566cb3651ddf5a59fbb3ac82399d358226e94204c1f5b712dbb7aa07f1868dcf0278edcc37708102bdd3b60"
		       );

	// test 2 step 5
	hdkat.setStep5(1536,
		       "895571dd4381d0da61e209cef170841013faba713995b53d691901993f9142ea084ef471966cec92a7487cc7593d25228e616caedbf9faa50cc013093363a424e8e24142aff71616c8b170d37b7a7a4ef1cd0c16766ee8b4af40f5005b8255caa42f6d5d17bf67f7e6d11a49b363e4",
		       "46c505af058b37dfd9f59932ac17048fb307ffc5c27195d8bacf5521f811c1f157ce7589258ef328a55f3aea70e4ab09880c59f55ea211681c18584465ce1732503d991566cb3651ddf5a59fbb3ac82399d358226e94204c1f5b712dbb7aa07f1868dcf0278edcc37708102bdd3b60",
		       "5d3d1c5ea9e8c219d43511288fc65dbc1a2f6284c59b26d4375f156b75d383d01ac6773cad41bf5b6d9fc41416933c0459f9b6d481412e38e9dde34cec3529a313d2e7815bc5c29a550dfd6be3365d0f8fbbe3a33bc07b6b96351834462a2e624d4ffa0bd1bf9adda378f4ddb6d4f6a99f7e3fa2556e52006b40fe9caa30ff4cbed3e574e2b3752680ce7117ab880dd3890be9c19f6442b0e2e04684e05f4fffd90f97112f0766a589ed82c07af7cba239c36a3d2bf52a25df2c84678556cedf"
		       );

	ret.add(hdkat);


	// return the result list
	return ret;
    }
    
    
    

    /**
     * Perform one or more known-answer tests on a HashDRBG.  This routine
     * must be called separately as part of application start-up testing, it
     * is not called from performSelfTest.
     *
     * POST-REVIEW NOTE:
     *   The review recommended validating the DRBG with NIST test vectors.
     *   That's what this method does.  See initializeTests() for the 
     *   particular tests performed.  
     *
     * @param log a Logger to which we can log dire messages
     * @return true if all the known answer tests pass, false if any facet of any fail
     */
    public static boolean performKnownAnswerTests(Logger log) {
	HashDRBG drbg;
	boolean pass = true;

	// get tests
	List<HashDRBGKnownAnswerTest> tests;
	tests = initializeTests();

	// run each test
	int tno = 1;
	int status;
	
	for(HashDRBGKnownAnswerTest test: tests) {
	    log.info("DRBG KAT - starting test " + tno + " at strength " + test.strength);

	    // step 1 - create
	    drbg = new HashDRBG("KAtest " + tno + " DRBG", test.getEntropySource());
	    drbg.setLogger(log);

	    // step 1 - checks
	    if (drbg.getReseedCounter() != test.step1_PostRSC) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 1 - post check on RSC failed, should be " + test.step1_PostRSC + " but was " + drbg.getReseedCounter());
	    } 


	    // step 2 - instantiate
	    status = drbg.instantiate(test.strength, false, null, test.step2_Nonce);
	    
	    // step 2 - checks
	    if (status != STATUS_SUCCESS) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 2 - instantiate call failed, returned " + status);
	    } 
	    if (!(drbg.v.equals(test.step2_PostV))) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 2 - post check on V failed, should be " + test.step2_PostV.toString(16) + " but was " + drbg.v.toString(16));
		log.info("\t\tsize of known answer=" + test.step2_PostV.bitLength() + " but size of DRBG value=" + drbg.v.bitLength());
	    } 
	    if (!(drbg.c.equals(test.step2_PostC))) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 2 - post check on C failed, should be " + test.step2_PostC.toString(16) + " but was " + drbg.c.toString(16));
	    } 
	    if (drbg.getReseedCounter() != test.step2_PostRSC) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 2 - post check on RSC failed, should be " + test.step2_PostRSC + " but was " + drbg.getReseedCounter());
	    } 

	    // step 3 - reseed
	    status = drbg.reseed(test.step3_AddlInput);

	    // step 3 - checks
	    if (status != STATUS_SUCCESS) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 3 - reseed call failed, returned " + status);
	    }
	    if (!(drbg.v.equals(test.step3_PostV))) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 3 - post check on V failed, should be " + test.step3_PostV.toString(16) + " but was " + drbg.v.toString(16));
	    }
	    if (!(drbg.c.equals(test.step3_PostC))) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 3 - post check on C failed, should be " + test.step3_PostC.toString(16) + " but was " + drbg.c.toString(16));
	    }
	    if (drbg.getReseedCounter() != test.step3_PostRSC) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 3 - post check on RSC failed, should be " + test.step3_PostRSC + " but was " + drbg.getReseedCounter());
	    }


	    // step 4 - generate 1
	    byte [] outbuf = new byte[test.step4_requestSize / 8];
	    status = drbg.generate(test.step4_requestSize / 8, 0, false, null, outbuf);

	    // step 4 - checks
	    if (status != STATUS_SUCCESS) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 4 - generate call failed, returned " + status);
	    }
	    if (!(drbg.v.equals(test.step4_PostV))) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 4 - post check on V failed, should be " + test.step4_PostV.toString(16) + " but was " + drbg.v.toString(16));
	    }
	    if (!(drbg.c.equals(test.step4_PostC))) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 4 - post check on C failed, should be " + test.step4_PostC.toString(16) + " but was " + drbg.c.toString(16));
	    }
	    if (drbg.getReseedCounter() != test.step4_PostRSC) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 4 - post check on RSC failed, should be " + test.step4_PostRSC + " but was " + drbg.getReseedCounter());
	    }


	    // step 5 - generate 2
	    status = drbg.generate(test.step5_requestSize / 8, 0, false, null, outbuf);

	    // step 5 - checks
	    if (status != STATUS_SUCCESS) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 4 - generate call failed, returned " + status);
	    }
	    if (!(drbg.v.equals(test.step5_PostV))) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 5 - post check on V failed, should be " + test.step5_PostV.toString(16) + " but was " + drbg.v.toString(16));
	    }
	    if (!(drbg.c.equals(test.step5_PostC))) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 5 - post check on C failed, should be " + test.step5_PostC.toString(16) + " but was " + drbg.c.toString(16));
	    }
	    if (!(Arrays.equals(test.step5_Output, outbuf))) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 5 - post check on output buffer failed, should be " + EntropyUtil.bufferToString(test.step5_Output) + "[" + test.step5_Output.length + "] but was " + EntropyUtil.bufferToString(outbuf) + "[" + outbuf.length + "]");
	    }
	    if (drbg.getReseedCounter() != test.step5_PostRSC) {
		pass = false;
		log.warning("In KnownAnswerTest, test " + tno + " step 5 - post check on RSC failed, should be " + test.step5_PostRSC + " but was " + drbg.getReseedCounter());
	    }

	    // step 6 - dispose
	    drbg.uninstantiate();
	}

	return pass;
    }

	
    
	/**
	 * Check that output buffer was actually overwritten with data,
	 * return false if buffer is still all zeros.
	 * 
	 * @param buf byte buffer of supposedly random data
	 * @return true if buf is not all zeros
	 */
	private boolean checkDRBGOutput(byte [] buf) {
		// first, perform a dumb test for all-zeros output
		int i; 
		for(i = 0; i < buf.length; i++) {
			if (buf[i] != (byte)0) return true;
		}
		
		return false;
	}

        /**
	 * Return the internal hash code length being used by
	 * this HashDRBG, in bytes.  (e.g. SHA1 would return 20)
	 */
	protected int getHashLength() {
		return hlength;
	}

	
	/**
	 * This utility method converts a byte buffer into a human-readable
	 * string representation.
	 * @param buf input buffer of bytes
	 * @return a String suitable for printing
	 */
	static String toString(byte [] buf) {
		StringBuffer sb = new StringBuffer(buf.length * 2 + 10);
		int i;
		int b;
		
		sb.append('[');
		for(i = 0; i < buf.length; i++) {
			b = (int) buf[i] & 0x0ff;
			if (b < 16) sb.append('0');
			sb.append(Integer.toHexString(b));
		}
		sb.append(']');
		
		return sb.toString();
	}

    
	
	/**
	 * Main method for unit test.
	 */
	public static void main(String [] args) {
		EntropySource lsrc = new LousyEntropySource();
		
		Logger log;
		log = Logger.getLogger("DRBGtest");
		log.setLevel(Level.FINEST);

		boolean result;
		System.err.println("Starting usual startup tests.");

		result = HashDRBG.performKnownAnswerTests(log);
		log.info("HashDRBG Test 1: performKnownAnswerTests result: " + result);
		if (!result) {
		    log.severe("HashDRBG Test 1: known answer tests failed!!!  Exiting!");
		    System.exit(1);
		}

		HashDRBG rnd;
		rnd = new HashDRBG("tester", lsrc);
		rnd.setLogger(log);
		
		result = rnd.performSelfTest();
		log.info("HashDRBG Test 2: performSelfTest result: " + result);
		
		if (args.length > 0) {
			byte [] output;
			output = new byte[16];
			System.err.println("Additional testing");
			rnd = new HashDRBG("tester2", lsrc);

			int status;
			status = rnd.instantiate(256, false, args[0], "foobarxxxxxx".getBytes());
			if (status == STATUS_SUCCESS) {
				System.err.println("instantiate succeeded.");
			} else {
				System.err.println("instantiate failed.");
			}

			Integer testint;
			testint = rnd.generateInteger(0);
			System.err.println("Generated random integer: " + testint);
			testint = rnd.generateInteger(0);
			System.err.println("Generated random integer: " + testint);
			testint = rnd.generateInteger(0);
			System.err.println("Generated random integer: " + testint);

			status = rnd.generate(16, 256, false, null, output);
			if (status == STATUS_SUCCESS) {
				System.err.println("generate succeeded.");
			} else {
				System.err.println("generate failed.");
			}

			output = new byte[164];
			status = rnd.generate(164, 256, false, null, output);
			if (status == STATUS_SUCCESS) {
				System.err.println("generate 2 succeeded.");
			} else {
				System.err.println("generate 2 failed.");
			}
			double chisq;
			chisq = EntropyUtil.chiSquaredStatistic(output, output.length, 3);
			System.err.println("Chi-squared statistic for 3 bit chunks = " + chisq);
			chisq = EntropyUtil.chiSquaredStatistic(output, output.length, 4);
			System.err.println("Chi-squared statistic for 4 bit chunks = " + chisq);

			status = rnd.reseed("self-test-2".getBytes());
			if (status == STATUS_SUCCESS) {
				System.err.println("reseed succeeded.");
			} else {
				System.err.println("reseed failed.");
			}			
			status = rnd.uninstantiate();
			if (status == STATUS_SUCCESS) {
				System.err.println("uninstantiate succeeded.");
			} else {
				System.err.println("uninstantiate failed.");
			}
			System.err.println("Rng reports okay " + rnd.isOkay());
		}
		
		
	}
}
