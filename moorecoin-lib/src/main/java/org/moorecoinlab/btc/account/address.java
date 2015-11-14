package org.moorecoinlab.btc.account;


import org.moorecoinlab.core.exception.moorecoinexception;

/**
 *
 * a bitcoin address is fundamentally derived from an elliptic curve public key and a set of network parameters.
 * it has several possible representations:<p>
 *
 * <ol>
 * <li>the raw public key bytes themselves.
 * <li>ripemd160 hash of the public key bytes.
 * <li>a base58 encoded "human form" that includes a version and check code, to guard against typos.
 * </ol><p>
 *
 * one may question whether the base58 form is really an improvement over the hash160 form, given
 * they are both very unfriendly for typists. more useful representations might include qrcodes
 * and identicons.<p>
 *
 * note that an address is specific to a network because the first byte is a discriminator value.
 */
public class address extends versionedchecksummedbytes {
    /**
     * construct an address from parameters and the hash160 form. example:<p>
     *
     * <pre>new address(networkparameters.prodnet(), hex.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));</pre>
     */
    public address(int ver, byte[] hash160) {
        super(ver, hash160);
        if (hash160.length != 20)  // 160 = 8 * 20
            throw new runtimeexception("addresses are 160-bit hashes, so you must provide 20 bytes");
    }

    /**
     * construct an address from parameters and the standard "human readable" form. example:<p>
     *
     * <pre>new address(networkparameters.prodnet(), "17kzeh4n8g49gfvddzsf8pjapfyod1mndl");</pre>
     */
    public address(int ver, string address) throws moorecoinexception {
        super(address);
        if (version != ver)
            throw new moorecoinexception("mismatched version number, trying to cross networks? " + version +
                    " vs " + ver);
    }

    /** the (big endian) 20 byte hash that is the core of a bitcoin address. */
    public byte[] gethash160() {
        return bytes;
    }
}
