package org.ripple.bouncycastle.bcpg;

/**
 * basic tags for compression algorithms
 */
public interface compressionalgorithmtags 
{
    public static final int uncompressed = 0;          // uncompressed
    public static final int zip = 1;                   // zip (rfc 1951)
    public static final int zlib = 2;                  // zlib (rfc 1950)
    public static final int bzip2 = 3;                 // bz2
}
