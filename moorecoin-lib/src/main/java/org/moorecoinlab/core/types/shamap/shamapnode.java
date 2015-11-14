package org.moorecoinlab.core.types.shamap;


import org.moorecoinlab.core.hash.halfsha512;
import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.hash.prefixes.prefix;
import org.moorecoinlab.core.serialized.bytessink;

abstract public class shamapnode {
    protected hash256 hash;

    // this saves a lot of instanceof checks
    public abstract boolean isleaf();
    public abstract boolean isinner();

    public shamapleaf asleaf() {
        return (shamapleaf) this;
    }
    public shamapinner asinner() {
        return (shamapinner) this;
    }

    abstract prefix hashprefix();
    abstract public void tobytessink(bytessink sink);

    public void invalidate() {hash = null;}
    public hash256 hash() {
        if (hash == null) {
            hash = createhash();
        }
        return hash;
    }
    public hash256 createhash() {
        halfsha512 half = halfsha512.prefixed256(hashprefix());
        tobytessink(half);
        return half.finish();
    }
    /**
     * walk any leaves, possibly this node itself, if it's terminal.
     */
    public void walkanyleaves(leafwalker leafwalker) {
        if (isleaf()) {
            leafwalker.onleaf(asleaf());
        } else {
            asinner().walkleaves(leafwalker);
        }
    }
}
