package gov.nsa.ia.drbg;

import gov.nsa.ia.util.SelfTestable;

/**
 * This interface declares the methods needed to
 * support the Get_entropy_input function of SP800-90.
 * Implementations of this interface must deliver
 * entropy upon request, though a request may block
 * until enough entropy is available.
 * 
 */
public interface EntropySource extends SelfTestable {
	/**
	 * Get requested entropy.  This method appends the
	 * entropy into the provided OutputStream.  Implementations
	 * may block until entropy is available.
	 * If the entropy cannot be delivered at all, then the
	 * implementation must return null (which means STATUS_ERROR).
	 * 
	 * @param requestedEntropy amount of entropy needed, in bits
	 * @param minOutputBytes minimum amount of output caller will accept, in bytes, usually reqEntropy/8
	 * @param maxOutputBytes maximum amount of output caller will accept, 0 for unlimited
	 * 
	 * @return byte array containing entropy (STATUS_SUCCESS) or null (STATUS_ERROR)
	 */
	public byte[] getEntropy(int requestedEntropyBits, int minOutputBytes, 
						  int maxOutputBytes);
	
	/**
	 * Return entropy gathered during self-test, if any. 
	 * Implementations may simply return null, if the entropy gathered
	 * during self-test is no longer available or is not valid.  This
	 * method must not throw any exceptions; if self-test failed then
	 * this method must return null.  If called multiple times, this
	 * method should return the same value, until the next time a
	 * self-test is performed.  Implementations need make no
	 * guarantees about the size or quality of the entropy returned
	 * from this method, except that it was part of a successful
	 * self-test.
	 * 
	 * @return byte array containing entropy gathered during self-test, or null
	 */
	public byte[] getSelfTestEntropy();
	
	/**
	 * Release any necessary resources that this EntropySource might
	 * have opened.  Implementations of this method must not throw any
	 * exceptions, and must be safe to call multiple times.
	 */
	public void dispose();

}
