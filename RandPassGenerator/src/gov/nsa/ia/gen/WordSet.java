package gov.nsa.ia.gen;

import java.util.*;
import java.io.*;
import java.net.*;
import java.util.logging.*;

import gov.nsa.ia.drbg.*;
import gov.nsa.ia.util.*;

/**
 * An instance of WordSet class loads up a dictionary, and then
 * generates random passphrases composed of works from the
 * dictionary.  Callers can specify a length range for the
 * words, which effectively means that the passphrases can be
 * generated from a subset of the dictionary.
 * Note that, when loading up the dictionary, 
 * duplicate words are dropped, so that the final
 * word set contains one of each unique word from the dictionary.
 * This means that all words in the dictionary or length-constrained
 * subset of the dictionary, have equal chance
 * of appearing in the output passphrase.
 *
 * The mechanisms used in this class are not especially
 * efficient, but they're not too bad - for the most frequently
 * used operation, getRandomWord, they're only about 4X worse
 * than minimum possible.
 *
 * @author nziring
 * Updated by amsagos
 */

public class WordSet {
    /** default path to the dictionary we will use */
    public static final String DATA_PATH = "wordlist.txt";

    /** default minimum word length for new instances of this class */
    public static final int DEFAULT_MIN_LENGTH = 3;
    /** default maximum work length for new instances of this class */
    public static final int DEFAULT_MAX_LENGTH = 12;

    // private state for instances of this class
    private ArrayList<String> basewords;
    private ArrayList<String> currentSet;
    //private int minLength;
    //private int maxLength;
    private int rlimit;
    private Logger logger;

    /**
     * Create the WordSet, using the supplied URL.  If null, then
     * attempt to use the default path.
     *
     * @param src URL to the word list (text file)
     * @param lg Logger to which to log messages
     */
    public WordSet(URL src, Logger lg) {
	logger = lg;
	if (src == null) {
	    src = getClass().getClassLoader().getResource(DATA_PATH);
	}

	if (src == null) {
	    logger.warning("WordSet unable to open word data - null URL");
	    basewords = null;
	    currentSet = null;
	    return;
	}

	int cnt;
	
	cnt = loadBaseWordsFromURL(src);

	if (cnt <= 0) {
	    logger.warning("WordSet - loading words from URL failed: " + src);
	    return;
	}

	setLengthRange(DEFAULT_MIN_LENGTH, DEFAULT_MAX_LENGTH);
	return;
    }

    /**
     * Load up the base wordset from the given URL.  Returns the count
     * of words loaded, or -1 on error.   All activities logged.
     *
     * POST-REVIEW NOTE:
     *   During loading, a HashSet is used, so that duplicate words
     *   are ignored.  The final set used will be the unique words
     *   that appeared in the URL.
     *
     * @param src URL from which to load the data, usually a file in the jar
     * @return number of words loaded, or -1 on error
     */
    public int loadBaseWordsFromURL(URL src) {
	int cnt = -1;

	try {
	    InputStream is = null;
	    is = src.openStream();
	    BufferedReader br;
	    br = new BufferedReader(new InputStreamReader(is));

	    logger.info("WordSet - successfully opened word data file: " + src);

	    String line;
	    HashSet<String> wordset = new HashSet<String>();
	    cnt = 0;
	    while((line = br.readLine()) != null) {
		line = line.trim();
		if (line.length() < 1) continue;
		wordset.add(line);
		cnt++;
	    }

	    logger.info("WordSet - loaded " + cnt + " words from data file, accepted " + wordset.size() + " unique words into candidate set.");
	    try { br.close(); } catch (Exception e2) { /* only throws if already closed */ }
	    try { is.close(); } catch (Exception e3) { /* only throws if already closed */ }
	    logger.info("WordSet - closed stream to data file");

	    basewords = new ArrayList<String>();
	    basewords.addAll(wordset);
	}
	catch (IOException e) {
	    logger.warning("WordSet - IO Exception on processing data file: " + e);
	}

	return cnt;
    }

    /**
     * Set the length range for returning words.  When words are later
     * retrieved from this WordSet, it won't return words of length
     * outside the range.  (This works by creating a fresh version of
     * the words array that can be indexed separately.)
     * Returns the number of words now available for random choices, it
     * is up to the caller to determine if that size set is usable.
     * 
     * @param minlen minimum length of word, 0 or more
     * @param maxlen maximum length of word, 2 or more
     * @return size of the new, reduced set, which may be 0
     */
    public int setLengthRange(int minlen, int maxlen) {
	int len, cnt;

	if (minlen < 0) throw new IllegalArgumentException("Minimum length cannot be negative");
	if (maxlen < 2) throw new IllegalArgumentException("Maximum length must be > 1");
	if (minlen >= maxlen) throw new IllegalArgumentException("Maximum length must be greater than minimum length");

	//minLength = minlen;
	//maxLength = maxlen;
	currentSet = new ArrayList<String>();
	cnt = 0;
	for(String s: basewords) {
	    len = s.length();
	    if (len >= minlen && len <= maxlen) {
		currentSet.add(s);
		cnt++;
	    }
	}

	// rlimit is used to eliminate the slight bias in random
	// selection that would occur if we just used straight random
	// integers
	rlimit = (Integer.MAX_VALUE / cnt) * cnt;

	return cnt;
    }

    /**
     * Return the length of the current length-constrained word set.
     */
    public int size() {
	if (currentSet == null) return 0;
	else return currentSet.size();
    }

    private static double LOG2 = Math.log(2.0);
    
    /**
     * Return the number of bits of entropy that can
     * be expected in one word selected from the set.
     * Basically log2(size).
     */
    public double bitsPerItem() {
	double size = size();
	double ret = Math.log(size) / LOG2;

	return ret;
    }
	


    /**
     * Retrieve a random word from the wordset, given a properly
     * instantiated AbstractDRBG.  If anything goes wrong, we return
     * null. 
     *
     * This implementation uses a very simple approach to getting
     * a uniformly distributed choice over the length-selected subset
     * of words.  <ol>
     * <li>For a subset of size M, define RLIM=(MaxInt / M) * M.</li>
     * <li>Let N be a random integer generated by the DRBG (32 bits of random)</li>
     * <li>IF N < 0 THEN go back to step 2</li>
     * <li>IF N >= RLIM THEN go back to step 2</li>
     * <li>Let N' = N % M</li>
     * <li>Let Word = CurrentWordSet[N']</li>
     * </ol>
     *
     * This is a rather wasteful of DRBG output bits, in the sense that
     * on average it will call getInteger() N times for 32 bits of random
     * each time (N=32/log2(M)) when it really needs only log2(M) bits.   
     * (M usually about 64K, so would be 16-17 bits, so we'll typically
     * need to call generateInteger about twice, therefore consuming
     * about 64 bits of random - 4x as much as we really need to.)
     * There is an optimal method I could have used, called
     * the Han-Hoshi algorithm, but it is considerably more complex and
     * difficult to ensure perfectly uniform selection when M is not a
     * power of 2.  So, I went with this simple method.
     *
     * @param drgb an initialized AbstractDRBG object
     * @return a word within the set length range, or null on error
     */
    public String getRandomWord(AbstractDRBG drbg) {
	int rval;
	int intsize;
	Integer r;

	rval = -1;

	intsize = 4;
	if (rlimit < (1<<20)) intsize = 3;
	if (rlimit < (1<<12)) intsize = 2;
	
	// keep getting random integers until we get a positive one
	// that is less than rlimit
	while (rval < 0 || rval >= rlimit) {
	    r = drbg.generateIntegerAtSize(0,intsize);
	    if (r == null) {
		logger.warning("WordSet - could not get random word, generateInteger returned null.");
		return null;
	    }
	    rval = r.intValue();
	}

	String ret;
	int i = rval % currentSet.size();
	ret = currentSet.get(i);

	return ret;
    }


    /**
     * Get a random list of words of a specified length.  
     * Returns the list as an array of Strings, or null if anything
     * goes wrong or if the len value supplied is 0 or negative.
     * 
     * Note that you can combine the strings into a conventional
     * space-separated passphrase as follows:
     *
     * <pre>
     *    String [] words = getRandomWordList(9, myDrbg);
     *    if (words == null) { // error handling here }
     *    StringJoiner joiner = new StringJoiner(" ");
     *    for(String w: words) { joiner.add(w); }
     *    String passphrase = joiner.toString();
     * </pre>
     *
     * @param len number of words to include in the list, 1 or more
     * @param drbg a usable AbstractDRBG, already instantiated
     * @return an array of Strings
     */
    public String[] getRandomWordList(int len, AbstractDRBG drbg) {
	int i;
	String [] results;

	if (len < 1) {
	    logger.warning("WordSet - bad length for getRandomWordList, 0 or negative, returning null");
	    return null;
	}

	results = new String[len];

	for(i = 0; i < len; i++) {
	    results[i] = getRandomWord(drbg);
	    if (results[i] == null) {
		logger.warning("WordSet - getRandomWord returned null, drbg problem, returning null.");
		return null;
	    }
	}

	return results;
    }


    /**
     * Get a random list of words of length sufficient to provide
     * the requested entropy.  
     * Returns the list as an array of Strings, or null if anything
     * goes wrong or if the entropy value requested is 0 or negative,
     * or if the entropy value requested is greater than the full
     * strength of the underlying DRBG.
     * 
     * @param strength strength value in bits entropy, usually 128, 160, or 256
     * @param drbg usable AbstractDRBG, already instantiated
     * @return array of strings, or null on any error
     */
    public String [] getRandomWordListByEntropy(int strength, AbstractDRBG drbg) {
	if (strength < 1) {
	    logger.warning("WordSet - bad strength value given, 0 or negative, returning null.");
	    System.err.println("Error - bad strength value given, 0 or negative, returning null.");
	    return null;
	}
	if (strength > (drbg.getStrength() * 2)) {
	    logger.warning("WordSet - strength request " + strength + " is greater than twice DRBG's underlying hash strength of " + drbg.getStrength() + ", returning null.");
	    System.err.println("Error - strength request " + strength + " is greater than twice DRBG's hash size of " + drbg.getStrength() + ".");
	    return null;
	}

	int len;
	double reqstr, wordstr, lenval;

	wordstr = bitsPerItem();
	reqstr = 1.0 * strength;
	lenval = reqstr / wordstr;
	lenval = Math.ceil(lenval);
	len = (int)lenval;

	return getRandomWordList(len, drbg);
    }


    /**
     * Randomly upcase the first N letters of a provided word,
     * drawing random from the given AbstractDRBG.  If N is greater
     * than or equal to the length of the input string, then all the
     * letters are potentially subject to uppercase.
     *
     * @param wrd A string composed of letters
     * @param n How many of the letters to possibly upcase at probability 1/2
     * @param drbg random source
     * 
     * @return a new string of same length with some letters possibly converted to uppercase
     */
    public String randomUpcase(String wrd, int n, AbstractDRBG drbg) {
	if (n <= 0) return wrd;
	
	int len = wrd.length();
	Integer ri;
	StringBuilder wb = new StringBuilder(len);

	for(int i = 0; i < len; i++) {
	    char c = wrd.charAt(i);
	    if (i < n) {
		ri = drbg.generateByte();
		if (ri == null) {
		    logger.warning("WordSet - generateByte returned null, drbg problem, cannot upcase.");
		    return null;
		}
		if (ri.intValue() > 127) {
		    c = Character.toUpperCase(c);
		}
	    }
	    wb.append(c);
	}
	return wb.toString();
    }

	/**
     * Randomly upcase the last N letters of a provided word,
     * drawing random from the given AbstractDRBG.  If N is greater
     * than or equal to the length of the input string, then all the
     * letters are potentially subject to uppercase.
     *
     * @param wrd A string composed of letters
     * @param n How many of the letters to possibly upcase at probability 1/2
     * @param drbg random source
     * 
     * @return a new string of same length with some letters possibly converted to uppercase
     */
    public String reverseRandomUpcase(String wrd, int n, AbstractDRBG drbg) {
		if (n <= 0) return wrd;
		
		int len = wrd.length();
		int y = len-n;			// Measuring from the end of the word, go back n letters, start Random Upcase at letters equal to y
		Integer ri;
		StringBuilder wb = new StringBuilder(len);
	
		for(int i = 0; i < len; i++) {
            char c = wrd.charAt(i);
            if (i >= y) {
                ri = drbg.generateByte();
                if (ri == null) {
                    logger.warning("WordSet - generateByte returned null, drbg problem, cannot upcase.");
                    return null;
                }
                if (ri.intValue() > 127) {
                    c = Character.toUpperCase(c);
                }
            }
            wb.append(c);   
        }

		return wb.toString();
		}

    // TESTING

    
    static byte [] nonceBytes = { (byte)0x01, (byte)0x02,
				  (byte)0x01, (byte)0x02,
				  (byte)0x01, (byte)0x02,
				  (byte)0x01, (byte)0x02,
				  (byte)0x01, (byte)0x02,
				  (byte)0x01, (byte)0x02,
				  (byte)0x01, (byte)0x02,
				  (byte)0x01, (byte)0x03
    };

    static int TESTCNT = 6;
    static int TESTSTRENGTH = 160;
    
    /**
     * main for unit testing - this main creates a HashDRBG and then
     * generates a large number of test words.
     *
     * The first command-line arg should be a URL of a word file.  On
     * most Linux systems, file:///usr/share/dict/words will work.
     */
    public static void main(String [] args) {
	int status;
	HashDRBG drbg;

	Logger log;
	log = Logger.getLogger("DRBGtest");
	log.setLevel(Level.FINE);
	
	EntropySource lsrc = new LousyEntropySource();

	drbg = new HashDRBG("wordset-selftest", lsrc);
	drbg.setLogger(log);
	boolean result;
	result = drbg.performSelfTest();
	if (!result) {
	    log.warning("WordSet test - DRBG self-test failed!!!");
	    System.exit(2);
	} else {
	    log.info("WordSet test - HashDRBG self-test passed.");
	}

	drbg = new HashDRBG("wordset-tester", lsrc);
	drbg.setLogger(log);

	log.info("WordSet test - created DRBG");

	status = drbg.instantiate(256, false, "foobar123", nonceBytes);
	if (status == DRBGConstants.STATUS_SUCCESS) {
	    log.info("WordSet test - instantiated DRBG ok!");
	} else {
	    log.warning("WordSet test - DRBG instantiation failed!");
	    System.exit(4);
	}

	for(String a: args) {
	    byte [] somebytes;
	    somebytes = a.getBytes();
	    status = drbg.reseed(somebytes);
	    if (status != DRBGConstants.STATUS_SUCCESS) {
		log.warning("WordSet test - could not add entropy to DRBG");
		System.exit(1);
	    } else {
		log.info("WordSet test - added some entropy to DRBG");
	    }
	}

	// create a URL from the first arg, if given
	URL src = null;
	if (args.length > 0) {
	    try {
		src = new URL(args[0]);
	    } catch (MalformedURLException mue) {
		log.warning("WordSet test - URL given but malformed.");
		System.exit(3);
	    }
	    log.info("WordSet test - will attempt to use " + src + " as word list");
	} else {
	    log.warning("WordSet test - no URL given");
	    log.info("Please supply the URL of a word dictionary file");
	    System.exit(4);
	}
	
	// if we get here, the DBRG is ready
	int ix, ct;
	String word;
	WordSet ws;
	ws = new WordSet(src, log);

	// test 1 - default lengths
	for(ix = 0; ix < TESTCNT; ix++) {
	    word = ws.getRandomWord(drbg);
	    System.err.println("WordSet test 1, word " + ix + ": " + word);
	}

	// test 2 - shorter length range
	ct = ws.setLengthRange(4, 7);
	log.info("WordSet test 2 - length range 4,7, cnt=" + ct);
	log.info("WordSet test 2 - entropy per word " + ws.bitsPerItem());
	for(ix = 0; ix < TESTCNT; ix++) {
	    word = ws.getRandomWord(drbg);
	    System.err.println("WordSet test 2, word " + ix + ": " + word);
	}

	// test 3 - medium length range, by entropy
	String [] passphrase;
	ct = ws.setLengthRange(3, 8);
	log.info("WordSet test 3 - length range 3,8, cnt=" + ct);
	log.info("WordSet test 3 - entropy per word " + ws.bitsPerItem());
	for(ix = 0; ix < TESTCNT; ix++) {
	    passphrase = ws.getRandomWordListByEntropy(TESTSTRENGTH, drbg);
	    if (passphrase == null) {
		System.err.println("WordSet test 3, error, passphrase null");
	    } else {
		StringJoiner joiner = new StringJoiner(" ");
		for(String w: passphrase) { joiner.add(w); }
		System.err.println("WordSet test 3, passphrase: " + joiner.toString());
	    }
	}

	// test 4 - random upcasing
	int ruc = 3;
	ct = ws.setLengthRange(3, 9);
	log.info("WordSet test 4 - length range 3,9, cnt=" + ct);
	log.info("WordSet test 4 - entropy per word " + ws.bitsPerItem());
	log.info("WordSet test 4 - random upcase first " + ruc + " letters");
	for(ix = 0; ix < TESTCNT; ix++) {
	    passphrase = ws.getRandomWordListByEntropy(TESTSTRENGTH, drbg);
	    if (passphrase == null) {
		System.err.println("WordSet test 3, error, passphrase null");
	    } else {
		StringJoiner joiner = new StringJoiner(" ");
		for(String w: passphrase) { joiner.add(ws.randomUpcase(w,ruc,drbg)); }
		System.err.println("WordSet test 4, passphrase: " + joiner.toString());
	    }
	}


	drbg.uninstantiate();
    }

}
	
