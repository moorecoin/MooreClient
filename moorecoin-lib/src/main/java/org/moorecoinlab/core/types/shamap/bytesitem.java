package org.moorecoinlab.core.types.shamap;


import org.moorecoinlab.core.hash.prefixes.prefix;
import org.moorecoinlab.core.serialized.bytessink;

public class bytesitem extends shamapitem<byte[]> {
    private byte[] item;

    public bytesitem(byte[] item) {
        this.item = item;
    }

    @override
    void tobytessink(bytessink sink) {
        sink.add(item);
    }

    @override
    public shamapitem<byte[]> copy() {
        return this;
    }

    @override
    public prefix hashprefix() {
        return new prefix() {
            @override
            public byte[] bytes() {
                return new byte[0];
            }
        };
    }
}
