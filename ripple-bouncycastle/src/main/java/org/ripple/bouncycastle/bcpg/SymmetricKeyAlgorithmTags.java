package org.ripple.bouncycastle.bcpg;

/**
 * basic tags for symmetric key algorithms
 */
public interface symmetrickeyalgorithmtags 
{
    public static final int null = 0;        // plaintext or unencrypted data
    public static final int idea = 1;        // idea [idea]
    public static final int triple_des = 2;  // triple-des (des-ede, as per spec -168 bit key derived from 192)
    public static final int cast5 = 3;       // cast5 (128 bit key, as per rfc 2144)
    public static final int blowfish = 4;    // blowfish (128 bit key, 16 rounds) [blowfish]
    public static final int safer = 5;       // safer-sk128 (13 rounds) [safer]
    public static final int des = 6;         // reserved for des/sk
    public static final int aes_128 = 7;     // reserved for aes with 128-bit key
    public static final int aes_192 = 8;     // reserved for aes with 192-bit key
    public static final int aes_256 = 9;     // reserved for aes with 256-bit key
    public static final int twofish = 10;    // reserved for twofish
}
