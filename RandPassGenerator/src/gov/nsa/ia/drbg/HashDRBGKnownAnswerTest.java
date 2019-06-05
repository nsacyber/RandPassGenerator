package gov.nsa.ia.drbg;

import gov.nsa.ia.util.*;
import java.math.BigInteger;


/**
 * A simple little class to hold the values associated with a HashDRBG
 * known-answer test.  The steps in a known-answer test are always
 * the same in the Hash_DRBG.txt test vectors file supplied by NIST.
 *
 * Step 1 - Create the DRBG
 *
 * Step 2 - Instantiate the DRBG with particular value for strength/entropy-input-len
 *           and fixed values for the entropy input, nonce, and personalization string
 *
 * Step 3 - Reseed the DRBG with a fixed value for entropy input and add'l input
 *
 * Step 4 - Generate output of fixed size
 *
 * Step 5 - Generate output of fixed size
 *
 * Step 6 [implicit] - dispose
 * 
 * After Step 2 and step 3, we must check the V, C, and rsc values of the HashDRBG
 * After Step 4, we must check the V, C, rsc, and output values.
 * After Step 5, we must check the V, C, and rsc values.
 *
 * Each instance of this class represents a single test.
 *
 * Each instance of this class instantiates a FixedValuesEntropySource to supply the
 * fixed entropy input values.  
 */
class HashDRBGKnownAnswerTest {
    int strength;
    FixedValuesEntropySource src;

    int step1_PostRSC = 0;

    String step2_EntropyInput;
    byte [] step2_Nonce;
    String personalizationString = null;  // always

    BigInteger step2_PostV;
    BigInteger step2_PostC;
    int step2_PostRSC = 1;

    String step3_EntropyInput;
    byte [] step3_AddlInput;
    
    BigInteger step3_PostV;
    BigInteger step3_PostC;
    int step3_PostRSC = 1;

    int step4_requestSize;

    BigInteger step4_PostV;
    BigInteger step4_PostC;
    int step4_PostRSC = 2;

    int step5_requestSize;

    BigInteger step5_PostV;
    BigInteger step5_PostC;
    int step5_PostRSC = 3;
    byte [] step5_Output;

    /**
     * Create the object to represent a HashDRBG known-answer test
     */
    public HashDRBGKnownAnswerTest(int str) {
	strength = str;
    }

    /**
     * Set values for step 2: entropy input, nonce, post-v, and post-c.
     */
    public void setStep2(String entropyInput, String nonce, String postV, String postC) {
	step2_EntropyInput = entropyInput;
	step2_Nonce = EntropyUtil.stringToBuffer(nonce);
	step2_PostV = new BigInteger(postV, 16);
	step2_PostC = new BigInteger(postC, 16);
    }

    /**
     * Set values for step 3: entropyInput, postV, and PostC.
     * Step 3 value for add'l input is always null.
     */
    public void setStep3(String entropyInput, String postV, String postC) {
	step3_EntropyInput = entropyInput;
	step3_PostV = new BigInteger(postV, 16);
	step3_PostC = new BigInteger(postC, 16);
    }

    /**
     * Set values for step 4: requested output length in bits, postV, postC, and
     *  expected output.
     * Note that add'l input is always null.
     */
    public void setStep4(int len, String postV, String postC) {
	step4_requestSize = len;
	step4_PostV = new BigInteger(postV, 16);
	step4_PostC = new BigInteger(postC, 16);
    }

    /**
     * Set values for step 4: requested output length in bits, postV, and postC.
     * Note that add'l input is always null.
     */
    public void setStep5(int len, String postV, String postC, String output) {
	step5_requestSize = len;
	step5_PostV = new BigInteger(postV, 16);
	step5_PostC = new BigInteger(postC, 16);
	step5_Output = EntropyUtil.stringToBuffer(output);
    }

    /**
     * Return the pre-loaded entropy source.  This has to be called
     * after setStep3 or later.
     */
    public FixedValuesEntropySource getEntropySource() {
	src = new FixedValuesEntropySource();
	src.addValue(step2_EntropyInput);
	src.addValue(step3_EntropyInput);

	return src;
    }

}


		    
