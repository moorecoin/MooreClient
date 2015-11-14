package org.moorecoinlab.crypto.ecdsa;

import org.moorecoinlab.core.utils;
import org.moorecoinlab.core.exception.moorecoinexception;
import org.moorecoinlab.core.hash.b58;
import org.moorecoinlab.crypto.sha512;
import org.ripple.bouncycastle.util.encoders.hex;

import java.io.unsupportedencodingexception;
import java.math.biginteger;

import static org.moorecoinlab.core.utils.doubledigest;

public class seed {
    // see https://wiki.ripple.com/account_family
    final byte[] seedbytes;

    public seed(byte[] seedbytes) {
        this.seedbytes = seedbytes;
    }

    @override
    public string tostring() {
        return b58.getinstance().encodefamilyseed(seedbytes);
    }

    public byte[] getbytes() {
        return seedbytes;
    }

    public ikeypair keypair() {
        return createkeypair(seedbytes, 0);
    }
    public ikeypair rootkeypair() {
        return createkeypair(seedbytes, -1);
    }

    public ikeypair keypair(int account) {
        return createkeypair(seedbytes, account);
    }

    public static seed frombase58(string b58) {
        return new seed(b58.getinstance().decodefamilyseed(b58));
    }

    public static seed frompassphrase(string passphrase) {
        return new seed(passphrasetoseedbytes(passphrase));
    }

    public static byte[] passphrasetoseedbytes(string phrase) {
        try {
            return new sha512(phrase.getbytes("utf-8")).finish128();
        } catch (unsupportedencodingexception e) {
            throw new runtimeexception(e);
        }
    }

    public static ikeypair createkeypair(byte[] seedbytes) {
        return createkeypair(seedbytes, 0);
    }

    public static ikeypair createkeypair(byte[] seedbytes, int accountnumber) {
        if(seedbytes.length != 16)
            throw new moorecoinexception("seedbytes must be 16 bytes: " + hex.tohexstring(seedbytes));
        biginteger secret, pub, privategen;
        // the private generator (aka root private key, master private key)
        privategen = computeprivategen(seedbytes);
        byte[] publicgenbytes = computepublicgenerator(privategen);

        if (accountnumber == -1) {
            // the root keypair
            return new keypair(privategen, utils.ubigint(publicgenbytes));
        }
        else {
            secret = computesecretkey(privategen, publicgenbytes, accountnumber);
            pub = computepublickey(secret);
            return new keypair(secret, pub);
        }

    }

    /**
     *
     * @param secretkey secret point on the curve as biginteger
     * @return corresponding public point
     */
    public static byte[] getpublic(biginteger secretkey) {
        return secp256k1.basepointmultipliedby(secretkey);
    }

    /**
     *
     * @param privategen secret point on the curve as biginteger
     * @return the corresponding public key is the public generator
     *         (aka public root key, master public key).
     *         return as byte[] for convenience.
     */
    public static byte[] computepublicgenerator(biginteger privategen) {
        return getpublic(privategen);
    }

    public static biginteger computepublickey(biginteger secret) {
        return utils.ubigint(getpublic(secret));
    }

    public static biginteger computeprivategen(byte[] seedbytes) {
        byte[] privategenbytes;
        biginteger privategen;
        int i = 0;

        while (true) {
            privategenbytes = new sha512().add(seedbytes)
                    .add32(i++)
                    .finish256();
            privategen = utils.ubigint(privategenbytes);
            if (privategen.compareto(secp256k1.order()) == -1) {
                break;
            }
        }
        return privategen;
    }

    public static biginteger computesecretkey(biginteger privategen, byte[] publicgenbytes, int accountnumber) {
        biginteger secret;
        int i;

        i=0;
        while (true) {
            byte[] secretbytes = new sha512().add(publicgenbytes)
                    .add32(accountnumber)
                    .add32(i++)
                    .finish256();
            secret = utils.ubigint(secretbytes);
            if (secret.compareto(secp256k1.order()) == -1) {
                break;
            }
        }

        secret = secret.add(privategen).mod(secp256k1.order());
        return secret;
    }
    /*
    public static byte[] passphrasetoseedbytes(string passphrase) {
        try {
            return quartersha512(passphrase.getbytes("utf-8"));
        } catch (unsupportedencodingexception e) {
            throw new runtimeexception(e);
        }
    }

    public static ikeypair createkeypair(byte[] seedbytes) {
        if(seedbytes.length != 16)
            throw new moorecoinexception("seedbytes must be 16 bytes: " + convert.bytestohex(seedbytes));
        biginteger secret, pub, privategen, order = secp256k1.order();
        //system.out.println("seed.createkeypair() order=" + order + ", " + order.tostring(16));
        byte[] privategenbytes;
        byte[] publicgenbytes;

        int i = 0, seq = 0;

        while (true) {
            privategenbytes = hashedincrement(seedbytes, i++);
            privategen = utils.ubigint(privategenbytes);
            if (privategen.compareto(order) == -1) {
                break;
            }
        }
        publicgenbytes = secp256k1.basepointmultipliedby(privategen);

        i=0;
        while (true) {
            byte[] secretbytes = hashedincrement(appendintbytes(publicgenbytes, seq), i++);
            secret = utils.ubigint(secretbytes);
            if (secret.compareto(order) == -1) {
                break;
            }
        }

        secret = secret.add(privategen).mod(order);
        pub = utils.ubigint(secp256k1.basepointmultipliedby(secret));

        return new keypair(secret, pub);
    }

    public static byte[] hashedincrement(byte[] bytes, int increment) {
        return halfsha512(appendintbytes(bytes, increment));
    }

    public static byte[] appendintbytes(byte[] in, long i) {
        byte[] out = new byte[in.length + 4];

        system.arraycopy(in, 0, out, 0, in.length);

        out[in.length] =     (byte) ((i >>> 24) & 0xff);
        out[in.length + 1] = (byte) ((i >>> 16) & 0xff);
        out[in.length + 2] = (byte) ((i >>> 8)  & 0xff);
        out[in.length + 3] = (byte) ((i)       & 0xff);

        return out;
    }*/

    public static ikeypair getkeypair(byte[] master_seed) {
        return createkeypair(master_seed);
    }

    public static ikeypair getkeypair(string master_seed_str) {
        return getkeypair(b58.getinstance().decodefamilyseed(master_seed_str));
    }

    //for btc convert ...
    public static byte[] genseedfrombtcpriv(byte[] priv) {
        if(priv.length != 32) throw new moorecoinexception("btc private key must be 32 bytes!");
        byte[] ret = utils.quartersha512(utils.doubledigest(priv));
        return ret;
    }

    public static byte[] genseedfrombtcpriv(string privstr) {
        byte[] priv = hex.decode(privstr);
        return genseedfrombtcpriv(priv);
    }

}
