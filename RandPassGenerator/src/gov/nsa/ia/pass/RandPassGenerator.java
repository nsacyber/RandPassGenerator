package gov.nsa.ia.pass;

import java.util.*;
import java.util.logging.*;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.io.*;
import gov.nsa.ia.drbg.*;
import gov.nsa.ia.gen.*;
import gov.nsa.ia.util.*;

/**
 * This class manages the generation process for passwords, 
 * passphrases, and raw keys that can be generated by the
 * RandPassGenerator utility.  This class uses the RandManager
 * class to manage its DRBG.
 *
 * This class uses the Java java.util.logging.Logger class to do
 * its logging to a file.
 *
 * This class accepts command-line argument via its main method.
 * Run it with no arguments at all to get a usage message.
 *
 * @author nziring
 *
 * Updated 20180925 by amsagos
 * Updated 20211204 by nlzirin
 */

public class RandPassGenerator {
    /**
     * Version string
     */
    public static final String VERSION = "RandPassGen 1.3.3 - 25 June 2022";

    /**
     * Path of the default log file
     */
    public static final String DEFAULT_LOGFILE = "randpass.log";
    public static final String DEFAULT_KEYLOGFILE = "randpassGenKeys.log";

    /**
     * Default strength of keys to generate, in bits.  (Note that this is
     * not related to the strength of the underlying DRBG, which is fixed
     * and defined in RandManager.java.)
     */
    public static final int DEFAULT_STRENGTH = 160;

    /**
     * Default file in which to save entropy data
     */
    public static final String DEFAULT_RAND_FILE = "randpass-extra-entropy.dat";

    /**
     * Default max length for words in a passphrase
     */
    public static final int MAX_WORD_LEN = 8;

    /**
     * Default min length for words in a passphrase
     */
    public static final int MIN_WORD_LEN = 3;

    /**
     * Default separator string to use if employing chunk formatting
     */
    public static final String DEFAULT_CHUNK_SEPARATOR = "-";
    

    private Logger logger;
    private Logger KeyLogger;
    private RandManager randman;
    boolean verbose;
    private PrintWriter outputWriter;
    boolean enc;

    // extra formatting
    private boolean useChunking = false;
    private int chunkSize = 0;
    private String chunkSep = null;
    
    /**
     * Print an error message to stderr
     */
    private void message(String s) {
	System.err.println(s);
    }
    /**
     * Print a message to stderr, if verbose is turned on.
     */    
    private void startmessage(String s) {
	if (verbose) System.err.println(s);
    }

    /**
     * Return the Logger we are using.
     */
    Logger getLogger() {
	return logger;
    }
    
    /**
     * Return the Key Logger we are using.
     */
    Logger getKeyLogger() {
	return KeyLogger;
    }

    /**
     * Initialize this RandPassGenerator using the supplied log file
     * and the supplied entropy startup file.
     * 
     * @param logfile Path to a writeable log file, null to log to stderr
     * @param pw A usable printwriter for output, may not be null
     * @param verbose if true, print verbose messages
     */
    public RandPassGenerator(String logfile, PrintWriter pw, boolean verbose) {
	boolean die = false;
	
	this.verbose = verbose;
	logger = Logger.getLogger("RandPassGen-log");
	
	if (logfile != null) {
	    FileHandler fh = null;
	    try {
		fh = new FileHandler(logfile);
		fh.setFormatter(new SimpleFormatter());
		logger.setLevel(Level.FINE);
		logger.addHandler(fh);
		logger.setUseParentHandlers(false);
	    } catch (IOException ie) {
		logger.warning("RandPassGenerator - could not open log output file " + logfile + " - all logging to console.");
	    }
	}
	
	//
	KeyLogger = Logger.getLogger("RandPassGenKeys-log");
	if (DEFAULT_KEYLOGFILE != null) {
	    FileHandler fh = null;
	    try {
		fh = new FileHandler(DEFAULT_KEYLOGFILE);
		fh.setFormatter(new SimpleFormatter());
		KeyLogger.setLevel(Level.FINE);
		KeyLogger.addHandler(fh);
		KeyLogger.setUseParentHandlers(false);
	    } catch (IOException ie) {
	    KeyLogger.warning("RandPassGenerator - could not open key log output file " + DEFAULT_KEYLOGFILE + " - all logging to console.");
	    }
	}

	// log that we've started up
	logger.info("RandPassGenerator - starting operation of " + VERSION);
	
	// set the output writer
	if (pw == null) {
	    logger.severe("RandPassGenerator - no output writer supplied, exiting.");
	    throw new IllegalArgumentException("Output print writer must not be null.");
	}
	outputWriter = pw;

	// create RandManager
	randman = new RandManager("RandPassGen", logger);

	// add primary source to RandManager
	EntropySource primarysrc = null;
	//FileEntropySource startupsrc = null;
	
	try {
	    //startupsrc = new FileEntropySource(entfile, 8, 4);
		primarysrc = new JavaSecRandEntropySource();
	    
	    randman.setPrimarySource(primarysrc);
	    
	    // 1.2 UPDATE: SP800-90A 8.6.7 states nonce should be a random value with at least (security_strength/2) bits of entropy. 
	    // The value could be acquired from the same source and at the same time as the entropy input (primarySource). Instead of saving entropy to a 
	    // file during shutdown for later use as the nonce entropy source or using the system time when an entropy file doens't exist, use same entropy source
	    // as primary entropy input for the DRBG seed. Also removes any concerns about saving entropy used for the DRBG seed on the system. 
	    //randman.setStartupSource(startupsrc);
	    randman.setStartupSource(primarysrc);

	    logger.info("RandPassGen - created randomness manager, about to initialize and perform self-test");

	    // call the static known answer test on our DRBG class, to make sure it works
	    if (randman.performDRBGKATest()) {
		startmessage("Random generator code known answers self-test passed.");
		logger.info("RandPassGen - underlying DRBG implementation known answer self-test passed.");
	    } else {
		logger.severe("RandPassGen - underlying DRBG implementation known answer self-test failed!  This should never happen.  JVM broken?  Exiting.");
		System.exit(1);
	    }


	    startmessage("Initializing randomness; this will take some time if system entropy isn't full.  Be patient, or go do something else on this computer to help the system gather more entropy.  Thank you.");

	    if (randman.initialize()) {
		logger.info("RandPassGen - initialization succeeded, proceeding to self-test.");
		if (randman.performSelfTest()) {
		    startmessage("Random generation manager self-tests passed.");
		} else {
		    System.err.println("Randomness self-test failed.  Exiting.");
		}
	    }

	}
	catch (Exception e) {
	    logger.severe("Exception in RandPassGenerator setup, fatal.");
	    message("Error in RandPassGen startup: " + e);
	    die = true;
	}

	if (die) {
	    throw new RuntimeException("Error in RandPassGen startup.");
	}
    }

    /**
     * Close down the RandManager and make this RandPassGenerator
     * unusable.  Only call this right before exiting.
     */
    public void close() {
	if (randman != null) {
	    logger.info("RandPassGen - shutting down RandManager");
	    randman.shutdown();
	    randman = null;
	}
    }
    
   
    /** 
     * Utility function for making passwords or hex keys easier to read
     * by adding in separators every so many characters.  This method 
     * accepts a source string, a separator string, and a number of 
     * characters per group, and returns a string with groups of characters
     * from the source separated by the separator.  The last group might
     * be short, if there are too few characters in the source.
     *
     * @param src source string
     * @param grpsize number of chars per group, must be positive, usual value is 4
     * @param sep separator string, usually a single character like " " or "-"
     * @return a string of the chars from src, with interspersed separators
     */
    public static String formatWithSeparators(String src, int grpsize, String sep) {
	if (src == null) return null;
	if (sep == null) return src;

	if (grpsize <= 0) throw new IllegalArgumentException("Group size must be >0");

	StringBuilder sb = new StringBuilder();

	int pos = 0;
	int epos;
	int max = src.length();
	String grp;

	for(pos = 0; pos < max; pos += grpsize) {
	    if (pos > 0) sb.append(sep);
	    epos = pos + grpsize;
	    if (epos > max) epos = max;
	    grp = src.substring(pos, epos);
	    sb.append(grp);
	}

	return sb.toString();
    }


    /**
     * Set up use of chunk formatting for generating keys and passwords.
     * (Chunk formatting doen not apply to passphrases).
     * To disable chunk formatting, set first parameter to 0 or negative.
     *
     * @param cs chunk size to use, positive (supply 0 to disable chunking)
     * @param csep string separator to use; if null, then use default
     */
    public void setChunkFormatting(int cs, String csep) {
	if (cs <= 0) {
	    useChunking = false;
	    chunkSize = 0;
	    chunkSep = null;
	} else {
	    useChunking = true;
	    chunkSize = cs;
	    chunkSep = csep;
	    if (chunkSep == null) chunkSep = DEFAULT_CHUNK_SEPARATOR;
	}
    }
    
    /**
     * Generate some passwords of a specified strength using a 
     * specified character set, or the default character set.
     * All passwords will be output to stdout.  To specify a
     * character set, the supplied string is examined, a lowercase
     * letter in the string causes the password to have lowercase
     * letters, uppercase letter adds uppercase, digit adds digits,
     * anything else adds basic punctutation.
     * 
     * If the charsetfile argument is supplied, then it is read 
     * and used to create the custom charset.  Note that 
     * charsets and charsetfile should not both be supplied, but
     * if they are then charsetfile takes precedence.
     *
     * @param count  how many passwords to generate, positive
     * @param strength password strength in bits, usually 128, 160, or 256
     * @param charsets  which charsets to use in the password, if null then use default
     * @param charsetfile a custom charset file to read, if null then use default
     * @return number of passwords generated, or -1 on error
     */
    public int generatePasswords(int count, int strength, String charsets, String charsetfile) {
	CharacterSet cs;
	AbstractDRBG drbg;

	if (count < 1) {
	    logger.warning("RandPassGen - count for passwords < 1, error");
	    message("Error - number of passwords must be > 0");
	    return -1;
	}
	
	drbg = randman.getDRBG();
	if (!(drbg.isOkay())) {
	    logger.severe("RandPassGen - DRBG is not ok, error");
	    message("Error - DRBG is not usable, sorry.");
	    return -1;
	}
	if (strength > (drbg.getStrength() * 2)) {
	    logger.warning("RandPassGen - requested password strength " + strength + " is greater than hash size of underlying DRBG.  Error.");
	    message("Error - requested password strength of " + strength + " is greater than the hash size of the underlying DRBG");
	    return -1;
	}

	cs = new CharacterSet(logger);
	if (charsetfile != null) {
	    BufferedReader br;
	    try {
		br = new BufferedReader(new FileReader(charsetfile));
		logger.info("Opened custom charset file " + charsetfile);

		String line;
		line = br.readLine();
		while(line != null) {
		    cs.addSet(line.trim());
		    line = br.readLine();
		}
		br.close();
	    } catch(IOException ie) {
		logger.severe("RandPassGen - unable to read custom character set file '" + charsetfile + "', cannot proceed.");
		message("Unable to read custom character set file.  Cannot proceed.");
		return -1;
	    }
	}
	else if (charsets != null) {
	    int ix;
	    for(ix = 0; ix < charsets.length(); ix++) {
		if (Character.isLowerCase(charsets.charAt(ix))) {
		    cs.addSet(CharacterSet.LOWERCASE_LETTERS);
		}
		else if (Character.isUpperCase(charsets.charAt(ix))) {
		    cs.addSet(CharacterSet.UPPERCASE_LETTERS);
		}
		else if (Character.isDigit(charsets.charAt(ix))) {
		    cs.addSet(CharacterSet.DIGITS);
		}
		else if (!(Character.isLetterOrDigit(charsets.charAt(ix)))) {
		    cs.addSet(CharacterSet.PUNCTUATION);
		}
	    }
	}

	// go to default if nothing was added
	if (cs.size() == 0) {
	    cs.addSet(CharacterSet.DEFAULT_USABLE);
	}

	logger.fine("RandPassGen - initialized password character set, size=" + cs.size());
	if (verbose) {
	    message("RandPassGen - initialized password character set, size=" + cs.size());
	}

	int i;
	String pass;
	ArrayList<String> passes = new ArrayList<String>(count);
	for(i = 0; i < count; i++) {
	    pass = cs.getRandomStringByEntropy(strength, drbg);
	    if (pass == null) {
		logger.warning("RandPassGen - character set password generator failed!  Error.");
		return -1;
	    } else {
		passes.add(pass);
	    }
	}

	logger.info("RandPassGen - generated " + passes.size() + " passwords at strength " + strength);
	
	for(String p: passes) {
	    if (useChunking) {
		outputWriter.println(formatWithSeparators(p, chunkSize, chunkSep));
	    } else {
		outputWriter.println(p);
	    }
	}
	outputWriter.flush();
	logger.info("RandPassGen - output passwords to designated output channel");

	return passes.size();
    }

    
    /**
     * Generate some passphrases of a specified strength using the
     * default word set.
     * All passphrases will be output to stdout.  
     *
     * @param count  how many passphrases to generate, positive
     * @param strength passphrase strength in bits, usually 128, 160, or 256
     * @param wordlist URL to the wordlist to use, or null for default
     * @param maxWordLen maximum length of a word to use in the passphrase, <3 means use default
     * @param ruc random upcase the first ruc letters, 0 or positive
     * @return number of passphrases generated, or -1 on error.
     */
    public int generatePassphrases(int count, int strength, URL wordlist, int maxWordLen, int ruc) {
	WordSet ws;
	AbstractDRBG drbg;

	if (count < 1) {
	    logger.warning("RandPassGen - count for passphrases < 1, error");
	    message("Error - number of passphrases must be > 0");
	    return -1;
	}
	if (ruc < 0) ruc = 0;
	
	drbg = randman.getDRBG();
	if (!(drbg.isOkay())) {
	    logger.severe("RandPassGen - DRBG is not ok, error");
	    message("Error - DRBG is not usable, sorry.");
	    return -1;
	}
	if (strength > (drbg.getStrength() * 2)) {
	    logger.warning("RandPassGen - requested passphrase strength " + strength + " is greater than hash size of underlying DRBG.  Error.");
	    message("Error - requested passphrase strength of " + strength + " is greater than the hash size of the underlying DRBG");
	    return -1;
	}

	ws = new WordSet(wordlist, logger);
	int maxlen = maxWordLen;
	if (maxlen <= MIN_WORD_LEN) {
	    maxlen = MAX_WORD_LEN;
	}
	ws.setLengthRange(MIN_WORD_LEN, maxlen);

	if (ws.size() == 0) {
	    logger.warning("RandPassGen - error initializing passphrase word set, cannot generate passphrases");
	    return -1;
	}

	logger.fine("RandPassGen - initialized passphrase word set, size=" + ws.size());

	int i;
	String [] passphrase;
	ArrayList<String> passes = new ArrayList<String>(count);
	for(i = 0; i < count; i++) {
	    passphrase = ws.getRandomWordListByEntropy(strength, drbg);
	    if (passphrase == null) {
		logger.warning("RandPassGen - word set passphrase generator failed!  Error.");
		return -1;
	    } else {
		StringJoiner sj = new StringJoiner(" ");
		for(String s: passphrase) {
		    String wrd;
		    // if ruc <= 0 then this has no effect
		    wrd = ws.randomUpcase(s, ruc, drbg);
		    if (wrd == null) {
			logger.warning("RandPassGen - fatal error in trying to randomly upcase a word");
			return -1;
		    }
		    // add word to the passphrase
		    sj.add(wrd);
		}
		passes.add(sj.toString());		
	    }
	}

	logger.info("RandPassGen - generated " + passes.size() + " passphrases at strength " + strength);
	
	for(String p: passes) {
	    outputWriter.println(p);
	}
	outputWriter.flush();
	logger.info("RandPassGen - output passphrases to designated output channel");

	return passes.size();
    }

	    
    /**
     * Generate some raw hexadecimal keys of 
     * specified strength.
     * All keys will be output to stdout.  
     *
     * @param count  how many keys to generate, positive
     * @param strength key strength in bits, usually 128, 160, or 256
     * @param enc 
     * @return number of passphrases generated, or -1 on error.
     */
    public int generateKeys(int count, int strength, boolean enc) {
	HexKeyGen kg;
	AbstractDRBG drbg;

	if (count < 1) {
	    logger.warning("RandPassGen - count for keys < 1, error");
	    message("Error - number of keys must be > 0");
	    return -1;
	}
	
	drbg = randman.getDRBG();
	if (!(drbg.isOkay())) {
	    logger.severe("RandPassGen - DRBG is not ok, error");
	    message("Error - DRBG is not usable, sorry.");
	    return -1;
	}
	if (strength > (drbg.getStrength() * 2)) {
	    logger.warning("RandPassGen - requested key strength " + strength + " is greater than hash size of underlying DRBG.  Error.");
	    message("Error - requested key strength of " + strength + " is greater than the hash size of the underlying DRBG");
	    return -1;
	}

	kg = new HexKeyGen(logger);

	logger.fine("RandPassGen - initialized hex key generator");

	int i;
	String rawkey;
	ArrayList<String> keys = new ArrayList<String>(count);
	ArrayList<String> hkeys = new ArrayList<String>(count);
	
	
	for(i = 0; i < count; i++) {
	    rawkey = kg.generateKey(strength, drbg);
	    if (rawkey == null) {
			logger.warning("RandPassGen - hex key generator failed!  Error.");
			return -1;
	    } else {
			keys.add(rawkey);
			
			//hash the generated keys to use for KEY_ID and add to the key generation transaction log
			MessageDigest messageDigest;
			try {
				messageDigest = MessageDigest.getInstance("SHA-384");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				throw new RuntimeException("Algorithm not installed.");
			}
			messageDigest.update(rawkey.getBytes());
			byte[] hk = messageDigest.digest(rawkey.getBytes(StandardCharsets.UTF_8));
			hkeys.add(bytesToHex(hk)); 
	    }
	}

	String keyfilename = null;
	
	logger.info("RandPassGen - generated " + keys.size() + " keys at strength " + strength);
	int a = 0;

	ArrayList<String> hkeyIDs = generateKeyIDList(hkeys);
	for(String p: keys) {
	    // TODO: refactor the code below to merge common output code
	    if (useChunking) {
		outputWriter.println(formatWithSeparators(p, chunkSize, chunkSep));
	    } else {
		outputWriter.println(p);
	    }	    

	    //print key ID
	    outputWriter.println("Key ID:");
	    outputWriter.println(hkeyIDs.get(a));
	    //print to key generation transaction log
	    KeyLogger.fine(hkeyIDs.get(a));		
	    keyfilename = hkeyIDs.get(a);
	    a++;

	    // if user asked for password encryption, create an encrypted file for
	    // just that particular key
	    if (enc) {
		encryptFileWithPassword(keyfilename, p);
		logger.fine("RandPassGen - encrypted key " + keyfilename + " with password");
	    }	
	}
	
	outputWriter.flush();
	logger.info("RandPassGen - output keys to designated output channel");

	return keys.size();
    }
     
    /**
     * Encrypt a file using standard password-based encryption.
     *
     * TODO: this encryption functionality is seriously crufty and 
     *    needs a rewrite.  Original version read a password with
     *    no display, once, so user couldn't see it!
     *       
     * Key File Encryption Prompt.
     * Encrypts generated key to a file using a password 
     * types by the user on system console.
     *
     * @param keyfilename name of the file to encrypt
     * @param input 
     */
    public static void encryptFileWithPassword(String keyfilename, String input) {
    	File encryptedFile = new File(keyfilename + ".enc");
    	Console br = System.console();
	System.out.println("Encrypting key file " + keyfilename);
    	System.out.print("Provide a random password of at least 16 characters: ");  
    	// Get the password from user.
    	String pass = null;
	pass = br.readLine();
	KeyWrapper.fileProcessor(pass.toCharArray(), input, encryptedFile);
    }
    
    /***
     * Decrypt an encrypted key file, using a password read from the console.
     *
     * TODO: the encrypt/decrypt functionality is seriously crufty and
     *    needs a rewrite.
     * 
     * Key File Decryption Prompt.
     * Decrypts user provided file using user provided password
     *
     * @param encryptedFile path to the encrypted file
     */
    public static void decryptPrompt(String encryptedFilePath) {
	   
	    File encryptedFile = new File(encryptedFilePath);

	    Console br = System.console();

	    System.out.println("Decrypting key file " + encryptedFilePath);
	    System.out.print("Provide the original encryption password: ");  
	    
	    String pass = null;
	    pass = br.readLine();
	    
	    //decrypt key file
	    File decryptedFile = new File(encryptedFilePath + "_decrypted.txt");
	    System.err.println("Attempting to decrypt input file to output " + decryptedFile);
	    KeyUnwrapper.fileProcessor(pass, encryptedFile, decryptedFile);
	    System.err.println("Wrote decrypted key to " + decryptedFile);
    }

    /**
     * Generate a list of Key IDs, given a list of key hashes.
     * 
     * Generates KeyID of key using first 64-bits of Hash and current date (YYYYMMDD_hhmmssH1H2H3H4H5H6H7H8H9H10H11H12H13H14H15H16).
     * 
     * @param hkeys an ArrayList of hashes of keys
     * @return an ArrayList of IDs
     */
    private static ArrayList<String> generateKeyIDList(ArrayList<String> hkeys)
    {
	ArrayList<String> fhkeys = new ArrayList<String>();
		
	for(String hhk: hkeys) {		
	    String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(Calendar.getInstance().getTime());
	    fhkeys.add(timestamp + hhk.substring(0,16));
	}
	return fhkeys;
     }
    
    /**
     * Byte to Hex converter.
     */
    private static String bytesToHex(byte[] hash) {
    StringBuffer hexString = new StringBuffer();
    for (int i = 0; i < hash.length; i++) {
       String hex = Integer.toHexString(0xff & hash[i]);
       if(hex.length() == 1) hexString.append('0');
           hexString.append(hex);
    }
    return hexString.toString();
    }

    /**
     * Set up the options manager for this RandPassGenerator.
     */
    private static OptionManager makeOptions() {
	OptionManager ret;
	ret = new OptionManager();

	ret.addOption("logfile", "Path to log file", true, "-log", DEFAULT_LOGFILE);
	ret.addOption("strength", "Bit strength of keys/passes to generate", true, "-str", "" + DEFAULT_STRENGTH);
	ret.addAlias("strength", "-s");
	//ret.addOption("randfile", "Path to file to use for saved entropy", true, "-randfile", DEFAULT_RAND_FILE);
	ret.addOption("passwords", "Number of random passwords to generate", true, "-pw", null);
	ret.addOption("passchars", "Non-default charset to use in passwords (usually 'aA9')", true, "-pwcs", null);
	ret.addOption("customfile", "File containing an explicit custom charset to use in passwords", true, "-pwcustom", null);
	ret.addOption("passphrases", "Number of random passphrases to generate", true, "-pp", null);
	ret.addOption("keys", "Number of raw hexadecimal keys to generate", true, "-k", null);
	ret.addOption("verbose", "Whether to print verbose messages", false, "-v", null);
	ret.addOption("wordlen", "Maximum length of words to use in passphrases", true, "-pplen", "" + MAX_WORD_LEN);
	ret.addOption("chunks", "Format output keys and passwords into chunks of length N", true, "-c", null);
	ret.addOption("separator", "String to use for separating chunks (default '-')", true, "-sep", "-"); 
	ret.addOption("wordlistURL", "URL of a list of words to use in passphrases", true, "-ppurl", null);
	ret.addOption("outfile", "Filename or path to which output should be written; otherwise output goes to stdout", true, "-out", null);
	ret.addOption("decrypt", "Decrypt an encrypted key file using password", true, "-decrypt", null);
	ret.addOption("enc", "Encrypt each key to a file using password (only for -k)", false, "-enc", null);
	ret.addOption("randUpcase", "For passphrases, apply uppercase randomly to first N letters of each word", true, "-rcc", null);
	return ret;
    }

    /**
     * Main method for the RandPassGenerator application - this method
     * processes the command-line args, then initializes the RandPassGenerator
     * and the RandManager, then generates the requested values.
     * 
     * This method uses
     */
    public static void main(String [] args) {
	int errs = 0;
	PrintWriter pw = null;
	
	OptionManager opt = makeOptions();

	if (args.length == 0) {
	    System.err.println("RandPassGenerator - exceptionally conservative utility for");
	    System.err.println("generating random keys, passwords, and passphrases");
	    System.err.println("at full cryptographic strength.");
	    System.err.println("");
	    System.err.println("Command-line options must be supplied.  Options are:");
	    System.err.println(opt.generateUsageText());
	    System.err.println("");
	    System.err.println("At least one of -pp, -pw, or -k must be provided.");
	    System.err.println("Keys, passwords, and passphrases written to stdout by default.");
	    System.err.println("");
	    System.err.println(VERSION);
	    System.exit(1);
	}

	// parse command-line args
	errs = opt.parseOptions(args);
	if (errs > 0) {
	    System.err.println("Command line had " + errs + " errors.");
	    System.err.println("Please fix errors and try again.  Exiting.");
	    System.exit(2);
	}

	// get necessary values
	int strength = opt.getValueAsInt("strength");
	int numPasswords = opt.getValueAsInt("passwords");
	int numPassphrases = opt.getValueAsInt("passphrases");
	int numKeys = opt.getValueAsInt("keys");
	boolean verbose = opt.getValueAsBoolean("verbose");
	String passwordCharset = opt.getValue("passchars");
	String passwordCustomCharsetFile = opt.getValue("customfile");
	String logfile = opt.getValue("logfile");
	//String randfile = opt.getValue("randfile");
	String outfile = opt.getValue("outfile");
	String ppurl = opt.getValue("wordlistURL");
	int maxWordLen = opt.getValueAsInt("wordlen");
	int chunksize = opt.getValueAsInt("chunks");
	String sep = opt.getValue("separator");
	String decryptFilePath = opt.getValue("decrypt");
	boolean enc = opt.getValueAsBoolean("enc");
	int randUpcase = opt.getValueAsInt("randUpcase");

	// check for something to do
	if (decryptFilePath != null) {
	    if (verbose) System.err.println("RandPassGen - attempting to decrypt encrypted key file " + decryptFilePath);
	    decryptPrompt(decryptFilePath);
	}
	
	if (numKeys <= 0 && numPasswords <= 0 && numPassphrases <= 0) {
	    System.err.println("No keys, passwords, or passphrases requested.  Exiting.");
	    System.exit(3);
	}
	
	// check that conflicting options were not supplied
	if (passwordCharset != null && passwordCustomCharsetFile != null) {
	    System.err.println("Option conflict: -pwcs and -pwcustom may not be supplied together.  Exiting.");
	    System.exit(4);
	}

	// prepare output file, if necessary
	if (outfile != null) {
	    pw = null;
	    try {
		pw = new PrintWriter(outfile);
	    } catch (IOException ie) {
		System.err.println("Error: could not write to output file '" + outfile + "', exiting.");
		System.exit(5);
	    }
	} else {
	    pw = new PrintWriter(System.out, true);
	}
	
	// ready to create the RandPassGenerator
	if (verbose) {
	    System.err.println(VERSION);
	    System.err.println("About to start initialization, requested key/passwd strength = " + strength);
	}

	if (logfile.equalsIgnoreCase("null") || logfile.equalsIgnoreCase("console") || logfile.equalsIgnoreCase("none") || logfile.equalsIgnoreCase("stderr")) {
	    logfile = null;
	    System.err.println("Logging will go to stderr.");
	}

	RandPassGenerator rpg = null;
	try {
	    rpg = new RandPassGenerator(logfile, pw, verbose);
	} catch (Exception e) {
	    System.err.println("Could not initialize RandPassGenerator: " + e);
	    if (verbose) {
		e.printStackTrace(System.err);
	    }
	    System.exit(6);
	}

	// set up chunking, if user options specify it
	rpg.setChunkFormatting(chunksize, sep);

	// set up the custom character set if user supplied a
	// custom character set file
	

	// Do the work that the user asked of us
	int cnt;
	if (rpg != null) {
	    if (numKeys > 0) {
	    	cnt = rpg.generateKeys(numKeys, strength, enc);
		if (cnt <= 0) {
		    rpg.message("Failed to generate keys");
		    rpg.getLogger().warning("Tried to generate " + numKeys + " keys, but failed.");
		} else {
		    rpg.message("Generated " + cnt + " keys at strength " + strength);
		}
	    }
	    if (numPasswords > 0) {
		cnt = rpg.generatePasswords(numPasswords, strength, passwordCharset, passwordCustomCharsetFile);
		if (cnt <= 0) {
		    rpg.message("Failed to generate passwords");
		    rpg.getLogger().warning("Tried to generate " + numPasswords + " passwords, but failed.");
		} else {
		    rpg.message("Generated " + cnt + " passwords at strength " + strength);
		}
	    }
	    if (numPassphrases > 0) {
		// figure out if we are doing random upcasing
		if (randUpcase <= 0) {
		    randUpcase = 0;
		} else {
		    if (verbose) {
			System.err.println("Using random upcase on first " + randUpcase + " letters.");
		    }
		    rpg.getLogger().info("Random upcase enabled for first " + randUpcase + " letters of passphrases");
		}

		// get the URL for the wordlist
		URL ppURL = null;
		if (ppurl != null && ppurl.length() > 0) {
		    try {
			ppURL = new URL(ppurl);
		    } catch (Exception ue) {
			rpg.getLogger().warning("RandPassGen - bad word list URL, exception: " + ue);
		    }
		}
		cnt = rpg.generatePassphrases(numPassphrases, strength, ppURL, maxWordLen, randUpcase);
		if (cnt <= 0) {
		    rpg.message("Failed to generate passphrases");
		    rpg.getLogger().warning("Tried to generate " + numPassphrases + " passphrases, but failed.");
		} else {
		    rpg.message("Generated " + cnt + " passphrases at strength " + strength);
		}
	    }
	  
	    rpg.close();
	}

	// flush and close the output PrintWriter if necessary
	if (pw != null) {
	    if (pw.checkError()) {
	    	System.err.println("Error: output stream reported an error; output might not be complete.");
	    }
	    pw.close();
	    pw = null;
	}

    }
	
}
