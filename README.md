# RandPassGenerator

The RandPassGenerator Java application is a simple command-line utility for generating random passwords, passphrases, and raw keys. It is designed very conservatively to ensure that the random values it provides offer full cryptographic strength requested by the user. This version of RandPassGenerator is only approved for generating random passwords and passphrases, it is not approved for the generation of raw keys.

### Usage Information


To use RandPassGenerator, you'll need the Oracle Java Runtime Environment; any recent version should be sufficient, but version 8 is recommended.

To run RandPassGenerator, once Java is installed, two batch script files have been provided (RandPasswordGenerator.bat and RandPassphraseGenerator.bat) to quickly generate a random password or passphrase. To use the scripts, unzip the RandPassGenerator.zip file in the C:\ drive (C:\RandPassGenerator) and run either the RandPasswordGenerator or RandPassphraseGenerator script. A text file containing the password or passphrase will be generated and saved in the C:\RandPassGenerator folder.

The RandPassGenerator can also run from a terminal or console. The command-line syntax is simple:

	java -jar RandPassGenerator.jar  [options]

### Options

-v	  {Print verbose messages during operation, in addition to logging}

-str S    {Use generation strength of S bits (default: 160)}

-pw N	  {Generate N random password of the specified strength}

-pp N	  {Generate N random passphrases of the specified strength}

-k N	  {Generate N random keys of the specified strength}

Unusual options:
  
-pplen M  {When generating passphrases, longest word should be M letters long (minimum value of M is 3)}

-ppurl U  {Use the URL U to load words for passphrase (default: use internal list)}

-pwcs P   {Use character pattern P for characters to use in passwords (lowercase, uppercase, number, special character, or combination)}

-log F    {Log all operations to the log file F (default: ./randpass.log)}

-randfile F  {Use file F for reading saved entropy on startup, and saving entropy on finish (default: randpass-extra-entropy.dat)}

-out F    {Write output to file F (default: writes to stdout)}

-c N 	    {Format output passwords and keys in chunks of N characters}

-sep S    {For chunk formatting, use S as the separator (default: -)}

At least one of the options -pw, -pp, or -k must be supplied. The keys, passwords, or passphrases produced by RandPassGenerator will be written to the standard output (stdout), so they can easily be redirected to a file. The -out option can also be used to write the output to a file. All messages are written to the standard error (stderr).

Detailed log messages are appended to the specified log file - if the log file cannot be opened, then the tool will not run. 

The option -randfile can be used to load additional entropy from a file. By default, the tool will attempt to save DRBG output to that file before exiting, so that the next run of the tool can benefit from the entropy gathered for this run. If the file cannot be written to, a message will be logged, but it isn't a fatal error.

 Note that the -pwcs option is a little strange. Each character in the value represents a full set of characters. Any lowercase letter
 means "add a character set of all lowercase letters", any uppercase letter means "add a set of all uppercase letter", any digit means 
"add a set of all digits", and anything else means "add a set of all punctuation marks". There is no way to supply a fully custom character set. Normally, you should not use the -pwcs option, you should let RandPassGenerator use its default character set.


## License

See [LICENSE](./LICENSE.md).

## Contributing

See [CONTRIBUTING](./CONTRIBUTING.md).

## Disclaimer

See [DISCLAIMER](./DISCLAIMER.md).


