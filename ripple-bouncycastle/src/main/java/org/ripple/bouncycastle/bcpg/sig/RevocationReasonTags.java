package org.ripple.bouncycastle.bcpg.sig;

public interface revocationreasontags
{
    public static final byte no_reason = 0;              // no reason specified (key revocations or cert revocations)
    public static final byte key_superseded = 1;         // key is superseded (key revocations)
    public static final byte key_compromised = 2;        // key material has been compromised (key revocations)
    public static final byte key_retired = 3;            // key is retired and no longer used (key revocations)
    public static final byte user_no_longer_valid = 32;  // user id information is no longer valid (cert revocations)

    // 100-110 - private use
}
