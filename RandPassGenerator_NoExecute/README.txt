RandPassGenerator 1.1.5


The RandPassGenerator Java application is a simple command-line utility 
for generating random passwords, passphrases, and raw keys.  It is designed
 very conservatively to ensure that the random values it provides offer full 
cryptographic strength requested by the user.

This version of RandPassGenerator is only approved for generating random passwords and passhrases, it is not approved for the generation of raw keys. 




USAGE INFORMATION


To use RandPassGenerator, you'll need the Oracle Java Runtime Environment;
any recent version should be sufficient, but version 8 is recommended.

 

To run RandPassGenerator, once Java is installed, two batch script files have been provided (RandPasswordGenerator.bat and RandPassphraseGenerator.bat) to quickly generate a random password or passphrase. To use the scripts, unzip the RandPassGenerator.zip file in the C:\ drive (C:\RandPassGenerator) and run either the RandPasswordGenerator or RandPassphraseGenerator script. A text file containing the password or passphrase will be generated and saved in the C:\RandPassGenerator folder. 

The RandPassGenerator can also run from
 a terminal or console.
The command-line syntax is simple:

	java -jar RandPassGenerator.jar  [options]


The following options are accepted:

  
Common options:
  
-v	  Print verbose messages during operation, in addition to logging
  
-str S    Use generation strength of S bits (default: 160)
  
-pw N	  Generate N random password of the specified strength
 
-pp N	  Generate N random passphrases of the specified strength
  
-k N	  Generate N random keys of the specified strength

 
Unusual options:
  
-pplen M  When generating passphrases, longest word should be M letters long
 (minimum value of M is 3) 
-ppurl U  Use the URL U to load words for passphrase (default: use internal list)	
  
-pwcs P   Use character pattern P for characters to use in passwords
 (lowercase letter, uppercase letter, number, special character, or combination) 
-log F    Log all operations to the log file F (default: ./randpass.log)
  
-randfile F  Use file F for reading saved entropy on startup, and saving entropy on finish (default: randpass-extra-entropy.dat)
  
-out F    Write output to file F (default: writes to stdout)
  
-c N 	  Format output passwords and keys in chunks of N characters
  
-sep S    For chunk formatting, use S as the separator (default: -)
  

At least one of the options -pw, -pp, or -k must be supplied.  The keys,
passwords, or passphrases produced by RandPassGenerator will be written 
to the standard output (stdout), so they can easily be redirected to a file.
 The -out option can also be used to write the output to a file.  All messages 
are written to the standard error (stderr).  

Detailed log messages are appended
 to the specified log file - if the log file cannot be opened, then the tool 
will not run. 

The option -randfile can be used to load additional entropy from a file. 
By default, the tool will attempt to save DRBG output to that file before
exiting, so that the next run of the tool can benefit from the entropy
gathered for this run.  If the file cannot be written to, a message will be
logged, but it isn't a fatal error.

Note that the -pwcs option is a little strange.  Each character in the 
value represents a full set of characters.  Any lowercase letter
means "add a character set of all lowercase letters", any uppercase
letter means "add a set of all uppercase letter", any digit means
"add a set of all digits", and any thing else means "add a set of all
punctuation marks".  There is no way to supply fully custom character
set.  Normally, you should not use the -pwcs option, you should let 
RandPassGenerator use its default character set.




Below are some examples of running RandPassGenerator in normal ways:



Example 1: generate 5 random passwords using the default mixed character set, at 
default strength of 160, saved into file GoodPasswords.dat

    java -jar PassGenerator.jar -pw 5  >GoodPasswords.dat




Example 2: generate 20 random passphrases using the default dictionary, at 
strength of 256, with verbose messages, using words up to 9 letters long, and
output saved into the file passphrases.txt

    java -jar PassGenerator.jar -v -pp 20 -str 256 -pplen 9 >passphrases.txt



Example 3: generate 200 random keys at strength of 192, with logging to keygen.log, and output to mykeys.out.

    java -jar PassGenerator.jar -k 200 -str 192 -log keygen.log -out mykeys.out



Example 4: generate 100 passwords at strength 160, using a character set of lowercase letters and digits, with output redirected to hi-quality-stuff.txt

    java -jar PassGenerator.jar -pw 100 -pwcs "a0"  >hi-quality-stuff.txt


Example 5: generate 10 passwords at strength 128, formatted into chunks of five characters each, separated by /.

    java -jar PassGenerator.jar -pw 10 -str 128 -c 5 -sep /
    





DESIGN INFORMATION


The foundation of RandPassGenerator is an implemention of the NIST SP800-90 Hash
DRBG.  It uses entropy, carefully gathered from system sources, to generate
quality random output.  The internal strength of the DRBG is 192 bits, according
 to NIST SP800-57, using the SHA-384 algorithm. In accordance with SP800-90,
the DRBG is seeded with at least 888 bits of high quality entropy from
 entropy sources prior to any operation.
 
This implementation uses the seed mechanism of the Java SecureRandom class for
gathering entropy. By default, it also saves entropy from run to run.

 This implementation performs self-tests at every execution, so that users
can be confident that no library problems have affected operation.  
Two kinds 
of self-tests are performed:
    
1. Known-answer tests from the NIST Hash_DRBG verification suite test file.
    
2. Simple statistical tests on DRBG output.

If the tests don't pass, the tool reports failure and refuses to run.

The strength mechanism implemented here is quite simple.  For passwords, the
 size of the character set used defines the bits-per-character, and password
length is then computed to meet or exceed the requested strength (typically,
this is somewhere around 5-6 bits per character).  Similarly, for passphrases 
the size of the usable dictionary defines the bits-per-word, and passphrase 
length is then computed to meet or exceed the requested strength (for the 
default dictionary and settings, roughly 16 bits per word).Duplicates are
 eliminated and the entropy is computed based on the number of unique
characters or words.

The RandPassGenerator tool performs extensive logging.  By default, log 
entries are appended to the local file "randpass.log".  No actual key data, random data, or seed data is written to the log file.


