package gov.nsa.ia.drbg;

import java.math.BigInteger;

/**
 * Some utility methods for helping self-test entropy sources.
 * @author nziring
 */
public class EntropyUtil {
	/**
	 * Check the 8-bit (byte) entropy of a buffer, return false if
	 * it doesnt exceed a supplied threshold.  
	 *
	 * @param buf byte buffer to be check
	 * @param len number of usable bytes in the buffer
	 * @param threshold minimum entropy that is acceptable
	 * @return false if computed entropy of bytes in buffer is LT threshold
	 */
	public static boolean checkByteEntropy(byte[] buf, int len, double threshold) {
		double h = 0.0;
		
		h = computeByteEntropy(buf, len);
		return (h >= threshold);
	}
	
	/**
	 * Compute the byte entropy of a sample, return it.
	 * @param buf buffer of bytes
	 * @param len number of bytes of data in the buffer
	 * @return shannon entropy of 8-bit chunks in the buffer
	 */
	public static double computeByteEntropy(byte [] buf, int len) {
		int count, mask;
		count = 256;
		mask = count - 1;
		int[] buckets;
		buckets = new int[count];
		double p[];

		if (len == 0) len = buf.length;
		int i;
		for (i = 0; i < len; i++) {
			buckets[(int) (buf[i]) & mask] += 1;
		}

		p = new double[count];
		for(i = 0; i < count; i++) {
			p[i] = ((double)buckets[i])/(double)len;
		}
		double sum;
		sum = 0.0;
		for(i = 0; i < count; i++) {
			if (p[i] > 0.0) sum += p[i] * log2(p[i]);
		}
		return -sum;
	}
	
	/**
	 * Max bit chunk sample size allowed for chi-squared computation
	 */
	public static final int MAX_CHISQ_SAMPLE_BITS = 16;
	
	/**
	 * Compute the chi-squared statistic of a byte buffer, using bit
	 * chunks of the specified size.  Usually, a good size is 4 or 6.
	 * Another rule of thumb is: set the bit size to s where
	 * 16 < (buflen*8 / 2^s); so for buflen of 128, use s=6 or s=5.
	 * If any of the arguments are invalid, 
	 * 
	 * @param buf buffer of bytes of ostensibly uniformly distributed bits
	 * @param len amount of buffer to use, 0 means use whole buffer
	 * @param chunkBits number of bits per sample, must be 2 or more
	 * @return pearson's chi-squared statistic for the samples, based on hypothesis of uniform distro
	 */
	public static double chiSquaredStatistic(byte [] buf, int len, int chunkBits) {
		// check args and make a BigInteger to hold all the bits
		if (buf == null || buf.length < 4) 
			throw new IllegalArgumentException("Byte buffer input too short");
		if (len == 0) len = buf.length;
		
		if (chunkBits < 2 || chunkBits > MAX_CHISQ_SAMPLE_BITS) 
			throw new IllegalArgumentException("Chunk size invalid, must be >=2 and <=" +
					MAX_CHISQ_SAMPLE_BITS);
		
		if (buf.length != len) {
			byte [] nb = new byte[len];
			System.arraycopy(buf, 0, nb, 0, len);
			buf = nb;
		}
		BigInteger bx = new BigInteger(buf);
		
		// create some bins and expected count per bin for uniform distro
		double realCounts[];
		double expectedCount;
		int numcounts; 
		numcounts = (1 << chunkBits);
		realCounts = new double[numcounts];
		expectedCount = (((double)(len*8)) / chunkBits)/numcounts;
		
		/*
		System.err.println("chiSquared debug: len of buf in bytes: " + len);
		System.err.println("chiSquared debug: chunkBits=" + chunkBits);
		System.err.println("chiSquared debug: numcounts=" + numcounts);
		System.err.println("chiSquared debug: expectedCount=" + expectedCount);
		*/
		
		// count the occurences in each bin
		int i, p, v;
		for(i = 0; i < len * 8; i += chunkBits) {
			v = 0;
			for(p = 0; p < chunkBits; p++) {
				v = (v << 1) | ((bx.testBit(i+p))?(1):(0));
			}
			realCounts[v] += 1.0;
		}
		
		// calculate the chi-squared statistic
		double sum = 0.0;
		double diff;
		for(i = 0; i < numcounts; i++) {
			diff = realCounts[i] - expectedCount;
			sum += (diff * diff)/expectedCount;
		}
		
		// return result
		return sum;
	}

	/**
	 * Chi-squared max values for 5% likelihood that the distro
	 * really is uniform, for various bit chunk sizes up to 16.
	 */
	static final double CHISQ_MAX_VALUES[] = 
	{
		0.0, 0.0, // sample bits 0 and 1, invalid
		5.99, 7.82,
		9.49, 11.1,
		12.6, 14.1,
		15.5, 16.9,
		18.3, 19.7,
		21.0, 22.4,
		23.7, 25.0,
		26.3
	};
	
	/**
	 * Test for whether a supposed uniform random distribution is actually
	 * satisfactorily uniform, based on 80% likelihood for chi-squared statistic.
	 * 
	 * @param chisq Chi-squared statistic, from chiSquaredStatistic method
	 * @param degfr sample size in bits, same as chunkBits, must be >=2 and <=16.
	 * @return true if chisq is under p=0.2 limit for deg of freedom, false otherwise
	 */
	public static boolean testChiSquared(double chisq, int degfr) {
		if (chisq < 0.0) throw new IllegalArgumentException("Bad chi-squared statistic value");
		if (degfr < 2 || degfr > MAX_CHISQ_SAMPLE_BITS)
			throw new IllegalArgumentException("Invalid sample size, must be >1 and <=" + 
					MAX_CHISQ_SAMPLE_BITS);
			
		double limit = EntropyUtil.CHISQ_MAX_VALUES[degfr];
		
		return (chisq <= limit);
	}
	
	public static final double LOG2 = 0.6931472;
	
	/**
	 * Compute the log base 2 of a number.
	 * @param x number to get log of
	 * @return the log base 2
	 */
	public static final double log2(double x) {
		return Math.log(x)/LOG2;
	}
	
	private static char nib[] = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', 
		'9', 'a', 'b', 'c', 'd', 'e', 'f'
	};
	
	/**
	 * Byte buf to String utility, for displaying buffers 
	 * to humans.
	 */
	public static String bufferToString(byte [] b) {
		StringBuilder sb = new StringBuilder(b.length * 2);
		int i;
		for(i = 0; i < b.length; i++) {
			sb.append(nib[(((int)b[i]) & 0x0f0) >> 4]);
			sb.append(nib[(((int)b[i]) & 0x0f)]);
		}
		return sb.toString();
	}

    /** 
     * String to byte buf utility, for accepting buffers more
     * easily.  This implementation adapted from the Sun source
     * code from com.sun.xml.internal.bind.DatatypeConverterImpl.java.
     */
    public static byte [] stringToBuffer(String s) {
	final int len = s.length();

	// "111" is not a valid hex encoding.
	if( len%2 != 0 ) return null;

	byte[] out = new byte[len/2];

	for( int i=0; i<len; i+=2 ) {
	    int h = hexToBin(s.charAt(i  ));
	    int l = hexToBin(s.charAt(i+1));
	    if( h==-1 || l==-1 ) return null;

	    out[i/2] = (byte)(h*16+l);
	}

	return out;
    }

    private static int hexToBin( char ch ) {
	if( '0'<=ch && ch<='9' )    return ch-'0';
	if( 'A'<=ch && ch<='F' )    return ch-'A'+10;
	if( 'a'<=ch && ch<='f' )    return ch-'a'+10;
	return -1;
    }



	/**
	 * Main method for unit testing.
	 *
	 * @param args ignored, for now
	 */
	public static void main(String args[]) {
		byte [] buf;
		
		buf = new byte[256];
		
		int i;
		for(i = 0; i < 256; i++) {
			buf[i] = (byte)i;
		}
		
		System.err.println("Unit test of EntropyUtil class.");
		
		double ent;
		ent = EntropyUtil.computeByteEntropy(buf, 0);
		System.err.println("Entropy of base buffer (should be 8): " + ent);
		double cs;
		cs = EntropyUtil.chiSquaredStatistic(buf, 0, 4);
		System.err.println("Chi-squared statistic for 4-bit samples (should be 0): " + cs);
		System.err.println("Test says: " + EntropyUtil.testChiSquared(cs, 4) + " (should be true)");
		cs = EntropyUtil.chiSquaredStatistic(buf, 0, 6);
		System.err.println("Chi-squared statistic for 6-bit samples (should be small): " + cs);
		System.err.println("Test says: " + EntropyUtil.testChiSquared(cs, 6) + " (should be true)");
		
		buf[14] = buf[57] = buf[90] = buf[113] = buf[168] = (byte)0;
		buf[29] = buf[64] = buf[127] = buf[149] = buf[199] = (byte)1;
		System.err.println("Corrupted the buffer, trying again...");
		System.err.println("Chi-squared statistic for 4-bit samples: " + cs);
		System.err.println("Test says: " + EntropyUtil.testChiSquared(cs, 4) + " (should be false)");
		cs = EntropyUtil.chiSquaredStatistic(buf, 0, 6);
		System.err.println("Chi-squared statistic for 6-bit samples: " + cs);
		System.err.println("Test says: " + EntropyUtil.testChiSquared(cs, 6) + " (should be false)");
				
	}
}
