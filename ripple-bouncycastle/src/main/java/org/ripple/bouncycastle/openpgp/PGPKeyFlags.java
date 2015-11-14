package org.ripple.bouncycastle.openpgp;

/**
 * key flag values for the keyflags subpacket.
 */
public interface pgpkeyflags
{
    public static final int can_certify = 0x01; // this key may be used to certify other keys.

    public static final int can_sign = 0x02; // this key may be used to sign data.

    public static final int can_encrypt_comms = 0x04; // this key may be used to encrypt communications.

    public static final int can_encrypt_storage = 0x08; // this key may be used to encrypt storage.

    public static final int maybe_split = 0x10; // the private component of this key may have been split by a secret-sharing mechanism.

    public static final int maybe_shared = 0x80; // the private component of this key may be in the possession of more than one person.
}
