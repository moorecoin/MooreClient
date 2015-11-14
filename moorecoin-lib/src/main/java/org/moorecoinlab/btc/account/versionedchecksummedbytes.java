package org.moorecoinlab.btc.account;


import org.moorecoinlab.btc.base58;
import org.moorecoinlab.btc.bitutil;
import org.moorecoinlab.core.exception.moorecoinexception;

import java.util.arrays;

/**
 * <p>in bitcoin the following format is often used to represent some type of key:</p>
 * <p/>
 * <pre>[one version byte] [data bytes] [4 checksum bytes]</pre>
 * <p/>
 * <p>and the result is then base58 encoded. this format is used for addresses, and private keys exported using the
 * dumpprivkey command.</p>
 */
public class versionedchecksummedbytes {
    protected int version;
    protected byte[] bytes;

    protected versionedchecksummedbytes(string encoded) throws moorecoinexception {
        byte[] tmp = base58.decodechecked(encoded);
        version = tmp[0] & 0xff;
        bytes = new byte[tmp.length - 1];
        system.arraycopy(tmp, 1, bytes, 0, tmp.length - 1);
    }

    protected versionedchecksummedbytes(int version, byte[] bytes) {
        assert version < 256 && version >= 0;
        this.version = version;
        this.bytes = bytes;
    }

    @override
    public string tostring() {
        // a stringified buffer is:
        //   1 byte version + data bytes + 4 bytes check code (a truncated hash)
        byte[] addressbytes = new byte[1 + bytes.length + 4];
        addressbytes[0] = (byte) version;
        system.arraycopy(bytes, 0, addressbytes, 1, bytes.length);
        byte[] check = bitutil.doubledigest(addressbytes, 0, bytes.length + 1);
        system.arraycopy(check, 0, addressbytes, bytes.length + 1, 4);
        return base58.encode(addressbytes);
    }

    @override
    public int hashcode() {
        return arrays.hashcode(bytes);
    }

    @override
    public boolean equals(object o) {
        if (!(o instanceof versionedchecksummedbytes)) return false;
        versionedchecksummedbytes vcb = (versionedchecksummedbytes) o;
        return arrays.equals(vcb.bytes, bytes);
    }

    /**
     * returns the "version" or "header" byte: the first byte of the data. this is used to disambiguate what the
     * contents apply to, for example, which network the key or address is valid on.
     *
     * @return a positive number between 0 and 255.
     */
    public int getversion() {
        return version;
    }
}
