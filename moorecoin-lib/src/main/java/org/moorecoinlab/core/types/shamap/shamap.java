package org.moorecoinlab.core.types.shamap;

import java.util.concurrent.atomic.atomicinteger;

public class shamap extends shamapinner {
    private atomicinteger copies;

    public shamap() {
        super(0);
        // this way we can copy the first to the second,
        // copy the second, then copy the first again ;)
        copies = new atomicinteger();
    }
    public shamap(boolean iscopy, int depth) {
        super(iscopy, depth, 0);
    }

    @override
    protected shamapinner makeinnerofsameclass(int depth) {
        return new shamap(true, depth);
    }

    public shamap copy() {
        version = copies.incrementandget();
        shamap copy = (shamap) copy(copies.incrementandget());
        copy.copies = copies;
        return copy;
    }

}
