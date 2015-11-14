package org.moorecoinlab.core.types.shamap;


import org.moorecoinlab.core.hash.halfsha512;
import org.moorecoinlab.core.hash.hash256;

/**

 * this is a toy implementation for illustrative purposes.
 */
public class nodestore {
    /**
    * in ripple, all data is stored in a simple binary key/value database.
    * the keys are 256 bit binary strings and the values are binary strings of
    * arbitrary length.
    */
    public static interface keyvaluebackend {
        void   put(hash256 key, byte[] content);
        byte[] get(hash256 key);
    }

    keyvaluebackend backend;
    public nodestore(keyvaluebackend backend) {
        this.backend = backend;
    }
    /**
     * all data stored is keyed by the hash of it's contents.
     * ripple uses the first 256 bits of a sha512 as it's 33 percent
     * faster than using sha256.
     *
     * @return `key` used to store the content
     */
    private hash256 storecontent(byte[] content) {
        halfsha512 hasher = new halfsha512();
        hasher.update(content);
        hash256 key = hasher.finish();
        storehashkeyedcontent(key, content);
        return key;
    }

    /**
     * @param hash as ripple uses the `hash` of the contents as the
     *             nodestore key, `hash` is pervasively used in lieu of
     *             the term `key`.
     */
    private void storehashkeyedcontent(hash256 hash, byte[] content) {
        // note: the real nodestore actually prepends some metadata, which doesn't
        // contribute to the hash.
        backend.put(hash, content); // metadata + content
    }

    /**
     * the complement to `set` api, which together form a simple public interface.
     */
    public byte[] get(hash256 hash) {
        return backend.get(hash);

    }
    /**
     * the complement to `get` api, which together form a simple public interface.
     */
    public hash256 set(byte[] content) {
        return storecontent(content);
    }
}