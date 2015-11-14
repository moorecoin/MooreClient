package org.moorecoinlab.core.types.shamap;


import org.moorecoinlab.core.vector256;
import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.hash.index;
import org.moorecoinlab.core.types.known.sle.ledgerentry;
import org.moorecoinlab.core.types.known.sle.ledgerhashes;
import org.moorecoinlab.core.types.known.sle.entries.directorynode;
import org.moorecoinlab.core.uint.uint32;

public class accountstate extends shamap {
    public accountstate() {
        super();
    }
    public accountstate(boolean iscopy, int depth) {
        super(iscopy, depth);
    }

    @override
    protected shamapinner makeinnerofsameclass(int depth) {
        return new accountstate(true, depth);
    }

    private static ledgerhashes newskiplist(hash256 skipindex) {
        ledgerhashes skip;
        skip = new ledgerhashes();
        skip.put(uint32.flags, new uint32(0));
        skip.hashes(new vector256());
        skip.index(skipindex);
        return skip;
    }

    public void updateskiplists(long currentindex, hash256 parenthash) {
        long prev = currentindex - 1;

        if ((prev & 0xff) == 0) {
            hash256 skipindex = index.ledgerhashes(prev);
            ledgerhashes skip = createorupdateskiplist(skipindex);
            vector256 hashes = skip.hashes();
            assert hashes.size() <= 256;
            hashes.add(parenthash);
            skip.put(uint32.lastledgersequence, new uint32(prev));
        }

        hash256 skipindex = index.ledgerhashes();
        ledgerhashes skip = createorupdateskiplist(skipindex);
        vector256 hashes = skip.hashes();

        if (hashes.size() > 256) throw new assertionerror();
        if (hashes.size() == 256) {
            hashes.remove(0);
        }

        hashes.add(parenthash);
        skip.put(uint32.lastledgersequence, new uint32(prev));
    }

    private ledgerhashes createorupdateskiplist(hash256 skipindex) {
        pathtoindex path = pathtoindex(skipindex);
        shamapinner top = path.dirtyorcopyinners();
        ledgerentryitem item;

        if (path.hasmatchedleaf()) {
            shamapleaf leaf = path.invalidatedpossiblycopiedleafforupdating();
            item = (ledgerentryitem) leaf.item;
        } else {
            item = new ledgerentryitem(newskiplist(skipindex));
            top.addleaftoterminalinner(new shamapleaf(skipindex, item));
        }
        return (ledgerhashes) item.entry;
    }

    public void addle(ledgerentry entry) {
        ledgerentryitem item = new ledgerentryitem(entry);
        additem(entry.index(), item);
    }

    public ledgerentry getle(hash256 index) {
        ledgerentryitem item = (ledgerentryitem) getitem(index);
        return item == null ? null : item.entry;
    }

    public directorynode getdirectorynode(hash256 index) {
        return (directorynode) getle(index);
    }

    public hash256 getnextindex(hash256 nextindex, hash256 bookend) {
        return null;
    }

    @override
    public accountstate copy() {
        return (accountstate) super.copy();
    }
}
