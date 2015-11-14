package org.moorecoinlab.core.types.shamap;


import org.moorecoinlab.core.hash.prefixes.prefix;
import org.moorecoinlab.core.serialized.bytessink;

abstract public class shamapitem<t> {
    abstract void tobytessink(bytessink sink);
    public abstract shamapitem<t> copy();
    public abstract prefix hashprefix();
}
