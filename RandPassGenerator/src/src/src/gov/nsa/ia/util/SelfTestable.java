package gov.nsa.ia.util;

/**
 * Classes which implement this interface
 * have the ability to perform a basic 
 * self-test.
 * 
 * @author nziring
 */
public interface SelfTestable {
	/**
	 * Return true if the self-test passes.  Return false if
	 * the self-test failed or was unable to be run.
	 */
	public boolean performSelfTest();
}
