package gov.nsa.ia.gen;

import java.util.logging.*;

import gov.nsa.ia.drbg.*;
import gov.nsa.ia.util.*;


/**
 * Generate a key expressed in raw hexadecimal.  Uses a DRBG
 * to generate the key bits, but returns them formatted in
 * hex.  Note that all hex digits will be uniformly distributed.
 *
 * This class does not apply any fancy formatting to the hex
 * output.  If the caller needs this, they must do it separately.
 *
 * @author nziring
 * Updated by amsagos
 */

public class HexKeyGen {
    // class internal state; just a logger to which to log any
    // error messages
    private Logger log;

    /**
     * Initialize a HexKeyGen object with a logger.
     */
    public HexKeyGen(Logger lg) {
	log = lg;
    }

    /**
     * Generate a key of the specified length in bits.   If the
     * requested strength is beyond the base strength of the DRBG,
     * returns null.
     * 
     * @param strength key strength in bits, must be positive multiple of 8, usually 128, 160, or 256
     * @param drbg Usable AbstractDRBG, already instantiated
     * @return hex string of a key, or null on any error
     */
    public String generateKey(int strength, AbstractDRBG drbg) {
	if (strength < 1) {
	    log.warning("CharacterSet - bad strength value given, 0 or negative, returning null.");
	    System.err.println("Error - bad strength value given, 0 or negative.");
	    return null;
	}
	if (strength > (drbg.getStrength() * 2)) {
	    log.warning("CharacterSet - strength request " + strength + " is greater than twice DRBG's hash size of " + drbg.getStrength() + ", returning null.");
	    System.err.println("Error - strength request " + strength + " is greater than twice DRBG's hash size of " + drbg.getStrength() + ".");
	    return null;
	}
	if (((strength / 8) * 8) != strength) {
	    log.warning("HexKeyGen - strength request " + strength + " must be a multiple of 8");
	    System.err.println("Error - strength request " + strength + " must be a multiple of 8");
	    return null;
	}

	int bytesNeeded = strength / 8;
	byte [] bytes = new byte[bytesNeeded];
	int status;

	status = drbg.generate(bytesNeeded, 0, false, null, bytes);

	if (status != DRBGConstants.STATUS_SUCCESS) {
	    log.warning("HexKeyGen - unable to generate key, DRBG failure.");
	    return null;
	}

	String ret;
	ret = EntropyUtil.bufferToString(bytes);

	return ret;
    }


    // TESTING
    

    static byte [] nonceBytes = { (byte)0x01, (byte)0x02,
				  (byte)0x01, (byte)0x02,
				  (byte)0x04, (byte)0x02,
				  (byte)0x05, (byte)0x02,
				  (byte)0x01, (byte)0x02,
				  (byte)0x01, (byte)0x02,
				  (byte)0x01, (byte)0x02,
				  (byte)0x0f, (byte)0x03
    };
    
    static int TESTCNT = 12;

    /**
     * Main for unit testing.  This function can be called by running
     * the CharacterSet class directly, to check basic functionality of
     * the class and its ability to interact with a DRBG.
     * Any arguments are simply fed to the DRBG as additional entropy.
     */
    public static void main(String [] args) {
	int status;
	HashDRBG drbg;

	Logger log;
	log = Logger.getLogger("DRBGtest");
	log.setLevel(Level.FINE);
	
	EntropySource lsrc = new LousyEntropySource();

	drbg = new HashDRBG("hexkeygen-selftest", lsrc);
	drbg.setLogger(log);
	boolean result;
	result = drbg.performSelfTest();
	if (!result) {
	    log.warning("HexKeyGen test - DRBG self-test failed!!!");
	    System.exit(2);
	} else {
	    log.info("HexKeyGen test - HashDRBG self-test passed.");
	}

	drbg = new HashDRBG("hexkeygen-tester", lsrc);
	drbg.setLogger(log);

	log.info("CharacterSet test - created DRBG");

	status = drbg.instantiate(256, false, "foobar789", nonceBytes);
	if (status == DRBGConstants.STATUS_SUCCESS) {
	    log.info("HexKeyGen test - instantiated DRBG ok!");
	} else {
	    log.warning("HexKeyGen test - DRBG instantiation failed!");
	    System.exit(4);
	}

	for(String a: args) {
	    byte [] somebytes;
	    somebytes = a.getBytes();
	    status = drbg.reseed(somebytes);
	    if (status != DRBGConstants.STATUS_SUCCESS) {
		log.warning("HexKeyGen test - could not add entropy to DRBG");
		System.exit(1);
	    } else {
		log.info("HexKeyGen test - added some entropy to DRBG");
	    }
	}

	int testno;
	int ix;
	HexKeyGen kg;
	String key;

	// test 1 - 128-bit keys
	testno = 1;
	kg = new HexKeyGen(log);
	for(ix = 0; ix < TESTCNT; ix++) {
	    key = kg.generateKey(128, drbg);
	    System.err.println("Test " + testno + " key " + ix + ": " + key);
	}

	// test 2 - 160-bit keys
	testno = 2;
	for(ix = 0; ix < TESTCNT; ix++) {
	    key = kg.generateKey(160, drbg);
	    System.err.println("Test " + testno + " key " + ix + ": " + key);
	}

	// test 2 - 256-bit keys
	testno = 3;
	for(ix = 0; ix < TESTCNT; ix++) {
	    key = kg.generateKey(256, drbg);
	    System.err.println("Test " + testno + " key " + ix + ": " + key);
	}


	drbg.uninstantiate();
    }

}	
	
