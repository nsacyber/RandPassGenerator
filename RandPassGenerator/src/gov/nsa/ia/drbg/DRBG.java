package gov.nsa.ia.drbg;

import gov.nsa.ia.util.SelfTestable;

/**
 * This interface declares the basic functions
 * that comprise a dterministic random bit
 * generator according to NIST SP800-90.
 * This is an attempt to be as faithful to SP800-90
 * as possible, while providing reasonable support
 * to Java programmers.
 * 
 * [Note that SP800-90 mandates the notion of a DRBG
 * entropy source, but does not incorporate management
 * of that entropy source into the basic API.  
 * Therefore, this interface does not provide any
 * methods related to the entropy source; see the 
 * AbstractDRGB class for more information.]
 * 
 * @see gov.nsa.ia.drbg.AbstractDRBG
 * @author nziring
 */
public interface DRBG extends DRBGConstants, SelfTestable {
	/**
	 * instantiate initializes the DRBG.  It must
	 * be called exactly once after creating the
	 * object but before using it for anything else.
	 * 
	 * @param requestedStrenth desired bit strength of DRBG, usually 256 or 512
	 * @param predictionResistanceFlag whether strong prediction resistance is to be used for all requests
	 * @param personalizationString additional seed data, optional but usually a good idea
	 * @param nonce additional seed data, optional but usually a good idea
	 * 
	 * @return STATUS_SUCCESS on successful initialization 
	 */
	public int instantiate(int requestedStrength,
							boolean predictionResistanceFlag,
							String personalizationString,
							byte [] nonce);
		
	
	/**
	 * Check usable status and strength of this DRBG.  This method is not mandated by
	 * SP800-90, but it may be useful.
	 *
	 * Get the instantiation bit strength of this DRBG.
	 * This will be the value passed to the instantiate() method, or
	 * 0 if the DRBG is not instantiated.
	 */
     public int getStrength();


	/**
	 * Uninstantiate the DRBG, wiping everything that can
	 * be wiped, and making the DRBG object unusable.
	 * Multiple calls are okay, but extra calls have no effect.
	 * Implementations may choose to prohibit instantiation after
	 * uninstantiation.
	 * 
	 * @return STATUS_SUCCESS is always returned
	 */
	public int uninstantiate();
	
	/**
	 * Re-seed the DRBG, utilizing the normal entropy source
	 * plus the supplied additional input, if any.  Note
	 * that if the DRBG has not been instantiated, or 
	 * has suffered a STATUS_CATASTROPHIC_ERROR,
	 * then this method will always return STATUS_ERROR.
	 * 
	 * @param additionalInput more entropy to push into the DRBG
	 * @return result status, usually STATUS_SUCCESS
	 */
	public int reseed(byte [] additionalInput);
	
	/**
	 * Generate pseudo-random bits (actually bytes) from this
	 * DRBG.  This method generates the requested number of
	 * bytes and writes them into the supplied array.
	 * Note that if the requestedStrength is greater than
	 * the strength requested at instantiation then this
	 * method should fail.  Also note that if prediction
	 * resistance was requested at instantiation, then the
	 * parameter predictionResistance is treated as always
	 * true. 
	 * <p>
	 * The argument order is a little strange, but that is
	 * the order defined in SP 800-90.
	 * </p><p>
	 * The usual way to call this is:
	 * <tt>
	 *   int status;
	 *   int size_needed;
	 *   byte rand_bytes[];
	 *   size_needed = 32;
	 *   rand_bytes = new byte[size_needed];
	 *   status = myDRBG.generate(size_needed, 0, true, null, rand_bytes);
	 *   if (status != DRBGConstants.STATUS_SUCCESS) { // do error handling }
	 * </tt>
	 * </p>
	 * 
	 * @param requestedStrength requested randomness bit strength (0 means instantiation strength)
	 * @param numBytes number of bytes of random output requested (8 bits per byte)
	 * @param predictionResistance whether prediction resistance is required for this request
	 * @param additionalInput more entropy to mix in before generation, optional
	 * @param output byte array for output, output.length must equal or exceed numBytes
	 * 
	 * @return result status, STATUS_SUCCESS if output was generated properly
	 */
	public int generate(int numBytes, int requestedStrength, boolean predictionResistance,
					    byte [] additionalInput, byte [] output);
	
	/*
	 * Methods not required in SP800-90 but which must be provided in 
	 * this implementation.
	 */
	
	/**
	 * Return the name of this DBRG.  Every DRBG instance has a name, which
	 * is analogous to the state handle in SP800-90.
	 */
	public String getName();

	/**
	 * Return a String representation of this DRBG.  The string
	 * description should include the name, the type of DRBG (such
	 * as "Hash" or "HMAC"), the strength, and the state.  Note that
	 * implementations should implement this method, because the
	 * default implementation provided by java.lang.Object does
	 * not include anything useful.
	 */
	public String toString();
	
}
