package org.ripple.bouncycastle.bcpg;

/**
 * basic tags for hash algorithms
 */
public interface hashalgorithmtags 
{
    public static final int md5 = 1;          // md5
    public static final int sha1 = 2;         // sha-1
    public static final int ripemd160 = 3;    // ripe-md/160
    public static final int double_sha = 4;   // reserved for double-width sha (experimental)
    public static final int md2 = 5;          // md2
    public static final int tiger_192 = 6;    // reserved for tiger/192
    public static final int haval_5_160 = 7;  // reserved for haval (5 pass, 160-bit)
    
    public static final int sha256 = 8;       // sha-256
    public static final int sha384 = 9;       // sha-384
    public static final int sha512 = 10;      // sha-512
    public static final int sha224 = 11;      // sha-224
}
