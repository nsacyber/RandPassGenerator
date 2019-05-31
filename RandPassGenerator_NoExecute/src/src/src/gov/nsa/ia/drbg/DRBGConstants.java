package gov.nsa.ia.drbg;

/**
 * This interface encapsulates the constants mandated
 * by NIST SP800-90.
 * 
 * @author nziring
 */
public interface DRBGConstants {
	/**
	 * Returned when the invokation is successful.
	 */
	public static final int STATUS_SUCCESS = 0;
	
	/**
	 * Returned when the invokation gets an error, but the
	 * DRBG is still in a usable state.
	 */
	public static final int STATUS_ERROR = -1;
	
	/**
	 * Returned when the DRBG has failed self-test or
	 * has otherwise entered an unusable state.
	 */
	public static final int STATUS_CATASTROPHIC_ERROR = -2;

	
}
