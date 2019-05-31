package gov.nsa.ia.util;

import java.util.*;


/**
 * OptionManager is a simple class to parse command-line options
 * and return their values in a variety of formats.  It can also
 * generate a "usage" listing of options.
 *
 * @author nziring
 */

public class OptionManager {

    class Option {
	/** false if this is a boolean option that takes no value argument */
	boolean needsValue;
	
	/** short name, by which values are retrieved, like "verbose" */
	String name;
	/** title/description for human user */
	String title;
	/** main option string to look for on command line, like "-v" */
	String opt;
	/** default value string, if any */
	String defaultValue;
    };


    /**
     * Option string map
     */
    private TreeMap<String, String> optmap;

    /**
     * Options map
     */
    private TreeMap<String, Option>  map;

    /**
     * Values parsed from a String[]
     */
    private TreeMap<String, String>  values;

    /**
     * Create an empty OptionManager object
     */
    public OptionManager() {
	map = new TreeMap<String, Option>();
	optmap = new TreeMap<String, String>();
	values = new TreeMap<String, String>();
    }

    /**
     * Add an option to the option map.
     *
     * @param name Name of the value
     * @param description Description of the option and its value
     * @param needsArg true if the option needs a following argument value
     * @param opt format of the option to match on command line
     * @param default default value, if any, may be null
     */
    public void addOption(String name, String desc, boolean needsArg,
			  String opt, String def)
    {
	Option newoption = new Option();

	newoption.name = name;
	newoption.title = desc;
	newoption.needsValue = needsArg;
	newoption.opt = opt;
        newoption.defaultValue = def;

	map.put(name, newoption);
	optmap.put(opt, name);
    }

    /**
     * Add an alias for an option
     * 
     * @param nam Name of a previously added option
     * @param opt another option value that should map to that name
     */
    public void addAlias(String nam, String opt) {
	optmap.put(opt, nam);
	return;
    }


    /**
     * Generate a "usage" message text of the available options
     * and return it as a big, multi-line string.   Must be done after
     * all the addOption calls.
     */
    public String generateUsageText() {
	StringBuilder sb = new StringBuilder();
	Option o;
	String n;
	
	for(String opt: optmap.keySet()) {
	    n = optmap.get(opt);
	    o = map.get(n);
	    sb.append(opt);
	    sb.append("\t");
	    sb.append(o.name);
	    sb.append(" - ");
	    sb.append(o.title);
	    if (o.defaultValue != null) {
		sb.append(" [default: ");
		sb.append(o.defaultValue);
		sb.append("]");
	    }
	    sb.append("\n");
	}

	return sb.toString();
    }
    
    /**
     * Retrieve a value that was parsed from the command line,
     * null if the option wasn't given and has no default.
     * (This function returns the string value, other methods will
     * parse as boolean or integer or float.)
     *
     * @param name Name of the value to retrieve
     * @return value provided, or default value, or null
     */
    public String getValue(String name) {
	String val;
	val = values.get(name);

	if (val == null) {
	    Option o;
	    o = map.get(name);
	    if (o != null) {
		if (o.defaultValue != null) {
		    val = o.defaultValue;
		}
	    }
	}

	return val;
    }

    /**
     * Return a value as an integer, or -1 if the option was not supplied.
     *
     * @param name Name of the option
     * @return integer value parse from string value of the option, or -1 if the option was not supplied and there is no default
     */
    public int getValueAsInt(String name) {
	int ival = -1;
	String val;
	val = getValue(name);

	if (val == null) return ival;
	
	try {
	    ival = Integer.parseInt(val);
	} catch (Exception e) {
	    System.err.println("Option " + name + " invalid integer given.");
	}

	return ival;
    }

    /**
     * Return a value as a boolean, false if the option wasn't supplied
     *
     * @param name Name of the option
     * @return boolean value
     */
    public boolean getValueAsBoolean(String name) {
	boolean bval = false;
	String val;
	Option o;
	o = map.get(name);
	val = getValue(name);

	if (o == null) return false;

	if (o.needsValue) {
	    if (val == null) {
		bval = false;
	    } else {
		// TODO: need to be more flexible here
		bval = Boolean.parseBoolean(val);
	    }

	} else {
	    bval = (val != null);
	}

	return bval;
    }

    /**
     * Parse an array of command-line args into the values
     * array.  Returns 0 on success, error count if any options
     * unrecognized or required arguments missing.
     *
     * @param args String[] of args, usually from value given to main
     * @return number of args unrecognized (error count)
     */
    public int parseOptions(String [] args) {
	int errcnt = 0;
	Option o;

	int i;
	String arg, nam, val;
	for(i = 0; i < args.length; i++) {
	    arg = args[i];
	    nam = optmap.get(arg);
	    if (nam == null) {
		errcnt += 1;
		System.err.println("Unrecognized option: " + arg);
	    }
	    else {
		o = map.get(nam);
		val = "";
		if (o.needsValue) {
		    val = o.defaultValue;
		    i = i + 1;
		    if (i >= args.length) {
			errcnt += 1;
			System.err.println("Option " + arg + " required value missing");
		    } else {
			val = args[i];
		    }
		}
		values.put(nam, val);
	    }
	}

	return errcnt;
    }
    

    // TESTING

    /**
     * Main for testing - test some option processing 
     */

    public static void main(String [] args) {
	OptionManager mgr;

	mgr = new OptionManager();
	mgr.addOption("file", "Path to input file", true, "-f", null);
	mgr.addAlias("file", "--file");
	mgr.addOption("size", "Number of records (int)", true, "-s", "10");
	mgr.addAlias("size", "--size");
	mgr.addAlias("size", "-C");
	mgr.addOption("verbose", "Print verbose message", false, "-v", null);


	if (args.length == 0) {
	    System.err.println("Usage:");
	    String usage = mgr.generateUsageText();
	    System.err.println(usage);
	}
	else {
	    int errs;
	    errs = mgr.parseOptions(args);
	    if (errs > 0) {
		System.err.println("Option errors: " + errs);
	    }

	    String fileVal;
	    int sizeVal;
	    boolean verboseVal;

	    fileVal = mgr.getValue("file");
	    sizeVal = mgr.getValueAsInt("size");
	    verboseVal = mgr.getValueAsBoolean("verbose");
	    
	    System.err.println("File option value: " + fileVal);
	    System.err.println("Size option value: " + sizeVal);
	    System.err.println("Verbose option value: " + verboseVal);

	}
    }

}
	
	
