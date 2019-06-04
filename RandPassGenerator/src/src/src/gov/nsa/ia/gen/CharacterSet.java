package gov.nsa.ia.gen;

import java.util.*;
import java.util.logging.*;

import gov.nsa.ia.drbg.*;
import gov.nsa.ia.util.*;


/**
 * The CharacterSet class represents a character list from which
 * a password could be created.  Callers can then ask for a string
 * of any length, composed of characters chosen uniformly from the
 * set.  Multiple instances of this class could potentiall be used for
 * creating more complexified passwords (e.g., 'pronouncable' 
 * passwords, passwords that obey silly complexity rules, or
 * passwords that have to pass character class presence checks) but
 * by itself this class does not offer such features.
 *
 * Actually, this class is mis-named; it should be CharacterList.
 * 
 * Note that the maximum size of the set is 32767.
 *
 * POST-REVIEW NOTES:
 *   This class allows use of character sets with repeated characters,
 *   which would change the relative frequency of characters in the output.
 *   However, the set is de-duped so that both sampling and entropy
 *   calculations use only unique characters in the character set.
 *   Therefore, it is not possible to use this class to make a 
 *   password where some characters (e.g., lowercase letters) appear
 *   more often than others (e.g., digits).  Such passwords might be
 *   useful in some contexts, but this class will make them.
 *
 * @author Neal Ziring
 */

public class CharacterSet {
    /** Uppercase letters for English */
    public static final String UPPERCASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /** lowercase letters for English */
    public static final String LOWERCASE_LETTERS = "abcdefghijklmnopqrstuvwxyz";

    /** digits */
    public static final String DIGITS = "0123456789";

    /** basic punctuation */
    public static final String PUNCTUATION = ".,:;-+";

    /** more punctuation chars, less commonly accepted */
    public static final String SPECIAL_CHARS = "\"'?/!~`|{}[]()^&%$#@*";

    /** base unambigous set, no 0 v O or l v 1, exactly 64 chars = 6 bits */
    public static final String DEFAULT_USABLE = "ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789.+:%#$";

    // internal class state

    // the list of characters that make up the set
    private char [] charset;

    // the source lists given to comprise the list
    private ArrayList<String> sets;

    // the logger channel to which to log errors messages
    private Logger logger;

    // the buffer of random shorts read from the DRBG, with index
    private short shortbuf[];
    private int   shortbufIndex;


    /**
     * Create an empty CharacterSet object.  The addSet method must
     * be called at least once before this CharacterSet is usable.
     *
     * @param lg initialized Logger for logging
     */
    public CharacterSet(Logger lg) {
	logger = lg;
	shortbuf = null;
	shortbufIndex = 0;
	charset = null;
	sets = new ArrayList<String>(5);
    }

    /**
     * Create a CharacterSet object, and addSet the given String.
     * All the chars in the String will be added to the charset
     * using addSet.
     *
     * @param lg initialized Logger for logging
     * @param s String full of characters
     */
    public CharacterSet(Logger lg, String s) {
	this(lg);
	addSet(s);
    }

    /**
     * Add a bunch of characters to the CharacterSet.  It is the
     * responsibility of the caller to look out for duplicate 
     * characters; if they're passed to this method, they'll be 
     * kept and the probability of that character being in the 
     * output will be higher.
     *
     * @param s String full of characters
     * @return length of the charset after all chars in s have been added
     */
    public int addSet(String s) {
	sets.add(s);

	reconstructCharSet();

	if (charset.length > 32767)
	    throw new RuntimeException("CharacterSet length limit exceeded!");

	return charset.length;
    }

    /**
     * rebuild the private variable charset.
     */
    private void reconstructCharSet() {
	StringBuilder sb = new StringBuilder();

	for(String x : sets) {
	    sb.append(x);
	}

	charset = uniqueCharset(sb.toString().toCharArray());

	// POST-REVIEW NOTE: when the charset is rebuilt, we reset
	// the buffer of shorts.   This doesn't actually matter, since
	// the buffer was just full of uniform full-range positive
	// shorts anyhow, but reviewers recommended this.
	shortbuf = null;
	shortbufIndex = 0;
    }

    /**
     * Return the length of the char set.
     */
    public int size() {
	if (charset == null) return 0;
	else return charset.length;
    }

    private static double LOG2 = Math.log(2.0);
    
    /**
     * Given an array of chars, return an array of chars
     * of equal or shorter length, containing only one of
     * each char that appears in the original.  This 
     * algorithm runs in time O(n * m) for n the number of
     * chars in the input and m the number of unique
     * chars.
     *
     * If given null, returns null.
     *
     * @param src source array of chars
     * @return char array with only unique chars
     */
    public final static char [] uniqueCharset(char [] src) {
	if (src == null) return null;

	char c;
	char [] tmp = new char[src.length];
	int sx = 0;
	int tx = 0;
	int tq = 0;

	for(sx = 0; sx < src.length; sx++) {
	    c = src[sx];
	    for(tq = 0; tq < tx; tq++) {
		if (c == tmp[tq]) break;
	    }
	    if (tq >= tx) {
		tmp[tx] = c;
		tx += 1;
	    }
	}

	char [] ret = new char[tx];
	// POST-REVIEW NOTES: fixed line below based on review
	System.arraycopy(tmp, 0, ret, 0, tx);

	return ret;
    }


    /**
     * Return the number of bits of entropy that can
     * be expected in one character from this set.
     * 
     * Basically log2(deduped size).
     *
     * POST-REVIEW NOTES: 
     *    Added code to count entropy based on number of
     *    unique characters in the set, rather than just size
     *    of the set.
     *    Later changed this class so that it ALWAYS uses the
     *    de-duped character set, eliminating the need to do
     *    anything special.
     *
     */
    public double bitsPerItem() {
	double size = charset.length;
	double ret = Math.log(size) / LOG2;
	return ret;
    }
	

    /**
     * Return the next uniformly distributed short int on the
     * range [0, maxval).  This uses a buffer of shorts which we
     * get from the drbg, refilling the buffer when needed.  If 
     * anything goes wrong, we return null.  
     *
     * Note that this method uses a simple resampling method to
     * ensure that the values we return are really uniformly 
     * distributed over the interval [0,max).
     *
     * @param max limit for return values
     * @param drbg random source for getting bytes, already instantiated
     * @return a positive short int N, 0<=N<max, or null on drbg error
     */
    private Short nextUniformShort(int max, AbstractDRBG drbg) {
	int rlim = (Short.MAX_VALUE / max) * max;
	int sval;
	do { 
	    if (shortbuf == null || shortbufIndex >= shortbuf.length) {
		int status;
		status = fillShortBuf(drbg);
		if (status != DRBGConstants.STATUS_SUCCESS) return null;
	    }

	    sval = shortbuf[shortbufIndex];
	    shortbufIndex += 1;
	} while (sval >= rlim);
	sval = sval % max;

	return new Short((short)(sval & 0x7fff));
    }

    private static final int BUFFER_FILL_SIZE = 24;

    /**
     * Fill a buffer with positive short integers, so that the caller
     * can have lots of them to use.  This modifies state variables,
     * and return the status code from the DRBG generate() method. 
     * Note that we're talking about positive shorts only, so each of
     * them effectively contains 15 bits of entropy.
     * 
     * @param drbg an AbstractDRBG, already instantiated
     * @return status code, if anything other than SUCCESS, then the buffer of shorts is worthless
     */
    private int fillShortBuf(AbstractDRBG drbg) {
	int status;
	int bytesNeeded;
	byte bytes[];

	bytesNeeded = BUFFER_FILL_SIZE * 2;
	bytes = new byte[bytesNeeded];
	status = drbg.generate(bytesNeeded, 0, false, null, bytes);
	if (status != DRBGConstants.STATUS_SUCCESS) return status;

	shortbuf = new short[BUFFER_FILL_SIZE];
	shortbufIndex = 0;
	
	int i, j;
	int val;
	short sval;
	for(i = 0, j = 0; j < BUFFER_FILL_SIZE; j++) {
	    val = bytes[i];
	    val = (val << 8) | bytes[i + 1];
	    i += 2;
	    sval = (short)(val & 0x7fff);
	    shortbuf[j] = sval;
	}

	return status;
    }
	   
    
    /**
     * Generate a string of the given length using randomness
     * taken from the supplied DRBG.
     *
     * @param len length of the String requested
     * @param drbg random generator, already instantiated
     * @return String of the requested length, or null if any error occurred
     */
    public String getRandomString(int len, AbstractDRBG drbg) {
	int i;
	int csSize;
	Short sv;
	short sval;

	if (len <= 0) {
	    logger.warning("CharacterSet - bad argument 0 or negative to getRandomString, returning null");
	    return null;
	}
	
	csSize = size();
	StringBuilder sb = new StringBuilder(len);

	for(i = 0; i < len; i++) {
	    sv = nextUniformShort(csSize, drbg);
	    if (sv == null) {
		logger.warning("CharacterSet - failed to get random value, DRBG failed, returning null.");
		return null;
	    }
	    sval = sv.shortValue();
	    sb.append(charset[sval]);
	}

	return sb.toString();
    }


    /**
     * Generate a string with the requested amount of entropy
     * from the given DRBG.  This works by calculating a length
     * and calling getRandomString.  If the strength requested is
     * greater than the overall strength of the DRBG, then we return
     * null.  On any error, we return null.
     *
     * @param strength strength value in bit-entropy, usually 128, 160, or 256
     * @param drbg  AbstractDRBG object, already instantiated
     * @return random string of appropriate length, or null
     */
    public String getRandomStringByEntropy(int strength, AbstractDRBG drbg) {
	if (strength < 1) {
	    logger.warning("CharacterSet - bad strength value given, 0 or negative, returning null.");
	    System.err.println("Error - bad strength value given, 0 or negative, returning null.");
	    return null;
	}
	if (strength > (drbg.getStrength() * 2)) {
	    logger.warning("CharacterSet - strength request " + strength + " is greater than twice the DRBG's hash size of " + drbg.getStrength() + ", returning null.");
	    System.err.println("Error - strength request " + strength + " is greater than twice DRBG's hash size of " + drbg.getStrength() + ".");
	    return null;
	}

	int len;
	double reqstr, charstr, lenval;

	charstr = bitsPerItem();
	reqstr = 1.0 * strength;
	lenval = reqstr / charstr;
	lenval = Math.ceil(lenval);
	len = (int)lenval;

	return getRandomString(len, drbg);
    }


    // TESTING

    static byte [] nonceBytes = { (byte)0x01, (byte)0x02,
				  (byte)0x01, (byte)0x02,
				  (byte)0x01, (byte)0x02,
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

	drbg = new HashDRBG("charset-selftest", lsrc);
	drbg.setLogger(log);
	boolean result;
	result = drbg.performSelfTest();
	if (!result) {
	    log.warning("CharacterSet test - DRBG self-test failed!!!");
	    System.exit(2);
	} else {
	    log.info("CharacterSet test - HashDRBG self-test passed.");
	}

	drbg = new HashDRBG("charset-tester", lsrc);
	drbg.setLogger(log);

	log.info("CharacterSet test - created DRBG");

	status = drbg.instantiate(256, false, "foobar456", nonceBytes);
	if (status == DRBGConstants.STATUS_SUCCESS) {
	    log.info("CharacterSet test - instantiated DRBG ok!");
	} else {
	    log.warning("CharacterSet test - DRBG instantiation failed!");
	    System.exit(4);
	}

	for(String a: args) {
	    byte [] somebytes;
	    somebytes = a.getBytes();
	    status = drbg.reseed(somebytes);
	    if (status != DRBGConstants.STATUS_SUCCESS) {
		log.warning("CharacterSet test - could not add entropy to DRBG");
		System.exit(1);
	    } else {
		log.info("CharacterSet test - added some entropy to DRBG");
	    }
	}

	int testno;
	int ix;
	CharacterSet cset;
	String pw;

	// test 1 - letters only, length of 12
	testno = 1;
	cset = new CharacterSet(log);
	cset.addSet(LOWERCASE_LETTERS);
	cset.addSet(UPPERCASE_LETTERS);
	System.err.println("Test " + testno + " bit strength per char is " + cset.bitsPerItem());
	for(ix = 0; ix < TESTCNT; ix++) {
	    pw = cset.getRandomString(12, drbg);
	    System.err.println("Test " + testno + " word " + ix + ": " + pw);
	}

	// test 2 - base usable character set, 160 bits of strength
	testno = 2;
	cset = new CharacterSet(log, DEFAULT_USABLE);
	System.err.println("Test " + testno + " bit strength per char is " + cset.bitsPerItem());
	for(ix = 0; ix < TESTCNT; ix++) {
	    pw = cset.getRandomStringByEntropy(160, drbg);
	    System.err.println("Test " + testno + " word " + ix + ": " + pw);
	}

	// test 3 - custom character set, 256 bits of strength
	testno = 3;
	cset = new CharacterSet(log);
	cset.addSet(DEFAULT_USABLE);
	cset.addSet("-_^!<>{}[]=()'");
	System.err.println("Test " + testno + " bit strength per char is " + cset.bitsPerItem());
	for(ix = 0; ix < TESTCNT; ix++) {
	    pw = cset.getRandomStringByEntropy(256, drbg);
	    System.err.println("Test " + testno + " word " + ix + ": " + pw);
	}

	// test 4 - custom character set with dupes
	testno = 4;
	cset = new CharacterSet(log);
	cset.addSet("abcdefghijklmnopqrstuvwxyz012345aaaaaabbbbcccc0000000000tttttttttttttttttt");
	cset.addSet("ggggggggghhhhhhhhhhhhjjjjjjjjjjjj");
	System.err.println("Test " + testno + " bit strength should be 5");
	System.err.println("Test " + testno + " bit strength per char is " + cset.bitsPerItem());
	for(ix = 0; ix < TESTCNT; ix++) {
	    pw = cset.getRandomStringByEntropy(64, drbg);
	    System.err.println("Test " + testno + " word " + ix + ": " + pw);
	}
	

	drbg.uninstantiate();
    }


}
