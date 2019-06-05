package gov.nsa.ia.util;

import java.math.BigInteger;
import java.util.LinkedList;
import gov.nsa.ia.drbg.EntropySource;
import gov.nsa.ia.drbg.EntropyUtil;

/**
 * The FixedValuesEntropySource is completely deterministic.
 * It holds a list of fixed values, and returns them in a cycle.
 * It is used only for performing known-answer tests.
 * 
 * @author nziring 
 */
public class FixedValuesEntropySource implements EntropySource {
    private LinkedList<byte []>  values;
    private int valueIndex;

    /**
     * Return our internal value, regardless of what length
     * was requested.   If this source has been dispose()ed 
     * then returns null.
     */
    public byte[] getEntropy(int requestedEntropyBits, int minOutputBytes, int maxOutputBytes) {
	if (values == null) return null;

	byte [] ret;
	ret = values.get(valueIndex % values.size());
	valueIndex = valueIndex + 1;

	return ret;
    }

    /**
     * Returns true if the internal value was initialized.
     */
    public boolean performSelfTest() {
	return (values != null);
    }
		
    /**
     * Always returns null.
     */
    public byte [] getSelfTestEntropy() {
	return null;
    }
		
    /**
     * Makes this entropy source unusable.
     */
    public void dispose() {
	values = null;
	valueIndex = 0;
	return;
    }

    /**
     * Create an 'entropy source' that returns a fixed list of values
     * cyclicly.   After calling this constructor, you must call 
     * addValue at least once.
     */
    public FixedValuesEntropySource() {
	values = new LinkedList<byte []>();
	valueIndex = 0;
    }	

    /**
     * Add a byte array value to this FixedValuesEntropySource.
     * This method accepts a hex string.
     */
    public void addValue(String valhex) {
	BigInteger v = new BigInteger(valhex, 16);
	byte [] value = pbi2ba(v);
	addValue(value);
    }

    /**
     * Add a byte array to this FixedValuesEntropySource.
     */
    public void addValue(byte [] val) {
	if (values != null) {
	    values.add(val);
	}
    }
    

    /**
     * Convert a non-negative Java BigInteger to a byte array,
     * but without the extra leading byte that sometimes appears to
     * hold the sign bit.
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



    static String [] testStrings = {
	"c14151651718191a1b1c1d1e1f223344556677889900aaff",
	"63363377e41e86468deb0ab4a8ed683f6a134e47e014c700454e81e95358a569",
	"303030303030ff30303030303030ff404040404040404040ff",
    };

    // Main for unit testing
    public static void main(String [] args) {
	boolean pass = false;
	
	System.err.println("Testing FixedValuesEntropySource.");

	FixedValuesEntropySource src = new FixedValuesEntropySource();
	for(String v: testStrings) {
	    src.addValue(v);
	}

	boolean pt = src.performSelfTest();
	System.err.println("\tdo-nothing self-test returns " + pt);

	int i;
	byte [] ev;
	String evStr;
	for(i = 0; i < 6; i++) {
	    ev = src.getEntropy(128, 16, 44); // params are ignored
	    evStr = EntropyUtil.bufferToString(ev);
	    System.err.println("\ti = " + i + " got back:");
	    System.err.println("\t" + evStr);
	    System.err.println("\t should be:");
	    System.err.println("\t" + testStrings[i % testStrings.length]);
	    if (!(evStr.equals(testStrings[i % testStrings.length]))) {
		pass = false;
		break;
	    } else {
		pass = true;
	    }
	}

	src.dispose();
	System.err.println("Self-test pass: " + pass);
    }
}	
