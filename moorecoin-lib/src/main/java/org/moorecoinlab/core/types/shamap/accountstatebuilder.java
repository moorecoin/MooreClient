package org.moorecoinlab.core.types.shamap;


import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.types.known.sle.ledgerentry;
import org.moorecoinlab.core.types.known.sle.threadedledgerentry;
import org.moorecoinlab.core.types.known.sle.entries.directorynode;
import org.moorecoinlab.core.types.known.sle.entries.offer;
import org.moorecoinlab.core.types.known.sle.entries.ripplestate;
import org.moorecoinlab.core.types.known.tx.result.affectednode;
import org.moorecoinlab.core.types.known.tx.result.transactionresult;

import java.util.*;

public class accountstatebuilder {
    private accountstate state;
    private accountstate previousstate = null;
    private long targetledgerindex;
    public long nexttransactionindex = 0;
    private hash256 targetaccounthash;
    public long totaltransactions = 0;

    private treeset<hash256> directoriesmodifiedmorethanoncebytransaction = new treeset<hash256>();
    private treeset<hash256> directoriesmodifiedbytransaction = new treeset<hash256>();

    public accountstatebuilder(accountstate state, long targetledgerindex) {
        this.state = state;
        setstatecheckpoint();
        this.targetledgerindex = targetledgerindex;
    }

    public void onledgerclose(long ledgerindex, hash256 accounthash, hash256 parenthash) {
        state.updateskiplists(ledgerindex, parenthash);
        targetledgerindex = ledgerindex;
        targetaccounthash = accounthash;
        nexttransactionindex = 0;
    }

    public void setstatecheckpoint() {
        previousstate = state.copy();
    }

    public void ontransaction(transactionresult tr) {
        if (tr.meta.transactionindex().longvalue() != nexttransactionindex) throw new assertionerror();
        if (tr.ledgerindex.longvalue() != targetledgerindex + 1) throw new assertionerror();
        nexttransactionindex++;
        totaltransactions++;
        directoriesmodifiedbytransaction = new treeset<hash256>();

        for (affectednode an : sortedaffectednodes(tr)) {
            hash256 id = an.ledgerindex();
            ledgerentry le = (ledgerentry) an.nodeasfinal();
            if (an.iscreatednode()) {
                le.setdefaults();
                state.addle(le);

                if (le instanceof offer) {
                    offer offer = (offer) le;
                    offer.setofferdefaults();

                    for (hash256 directory : offer.directoryindexes()) {
                        directorynode dn = getdirectoryforupdating(directory);
                        hash256 index = offer.index();
                        addtodirectorynode(dn, index);
                    }
                } else if (le instanceof ripplestate) {
                    ripplestate state = (ripplestate) le;

                    for (hash256 directory : state.directoryindexes()) {
                        directorynode dn = getdirectoryforupdating(directory);
                        addtodirectorynode(dn, state.index());
                    }
                }
                if (le instanceof threadedledgerentry) {
                    threadedledgerentry tle = (threadedledgerentry) le;
                    tle.previoustxnid(tr.hash);
                    tle.previoustxnlgrseq(tr.ledgerindex);
                }
            } else if (an.isdeletednode()) {
                directoriesmodifiedmorethanoncebytransaction.remove(id);
                state.removeleaf(id);
                if (le instanceof offer) {
                    offer offer = (offer) le;
                    for (hash256 directory : offer.directoryindexes()) {
                        try {
                            directorynode dn = getdirectoryforupdating(directory);
                            if (dn != null) {
                                hash256 index = offer.index();
                                if (dn.owner() != null) {
                                    directoryremoveunstable(dn, index);
                                } else {
                                    directoryremovestable(dn, index);
                                }
                            }
                        } catch (exception e) {
                            //
                        }
                    }
                } else if (le instanceof ripplestate) {
                    ripplestate state = (ripplestate) le;
                    for (hash256 directory : state.directoryindexes()) {
                        try {
                            directorynode dn = getdirectoryforupdating(directory);
                            if (dn != null) {
                                directoryremoveunstable(dn, state.index());
                            }
                        } catch (exception e) {
                            //
                        }
                    }
                }
            } else if (an.ismodifiednode()) {
                shamapleaf leaf = state.getleafforupdating(id);
                ledgerentryitem item = (ledgerentryitem) leaf.item;
                ledgerentry lemodded = item.entry;

                if (le instanceof threadedledgerentry) {
                    threadedledgerentry tle = (threadedledgerentry) le;
                    tle.previoustxnid(tr.hash);
                    tle.previoustxnlgrseq(tr.ledgerindex);
                }
                for (field field : le) {
                    if (field == field.ledgerindex) {
                        continue;
                    }
                    lemodded.put(field, le.get(field));
                }
            }
        }
    }

    public static <e> collection<e> makecollection(iterable<e> iter) {
        collection<e> list = new arraylist<e>();
        for (e item : iter) {
            list.add(item);
        }
        return list;
    }
    private arraylist<affectednode> sortedaffectednodes(transactionresult tr) {
        arraylist<affectednode> sorted = new arraylist<affectednode>(makecollection(tr.meta.affectednodes()));
        collections.sort(sorted, new comparator<affectednode>() {
            @override
            public int compare(affectednode o1, affectednode o2) {
                return ord(o1) - ord(o2);
            }

            private int ord(affectednode o1) {
                switch (o1.ledgerentrytype()) {
                    case directorynode:
                        return 1;
                    case ripplestate:
                        return 2;
                    case offer:
                        return 3;
                    default:
                        return 4;
                }
            }
        });
        return sorted;
    }

    private void ondirectorymodified(directorynode dn) {
        hash256 index = dn.index();
        if (directoriesmodifiedbytransaction.contains(index)) {
            directoriesmodifiedmorethanoncebytransaction.add(index);
        }
        else {
            directoriesmodifiedbytransaction.add(index);
        }
    }
    private void directoryremovestable(directorynode dn, hash256 index) {
        ondirectorymodified(dn);
        dn.indexes().remove(index);
    }
    private void directoryremoveunstable(directorynode dn, hash256 index) {
        ondirectorymodified(dn);
        dn.indexes().removeunstable(index);
    }
    private void addtodirectorynode(directorynode dn, hash256 index) {
        ondirectorymodified(dn);
        dn.indexes().add(index);
    }
    private directorynode getdirectoryforupdating(hash256 directoryindex) {
        shamapleaf leaf = state.getleafforupdating(directoryindex);
        if (leaf == null) {
            return null;
        }
        ledgerentryitem lei = (ledgerentryitem) leaf.item;
        return (directorynode) lei.entry;
    }

    public accountstate state() {
        return state;
    }

    public long currentledgerindex() {
        return targetledgerindex;
    }

    public string targetaccounthashhex() {
        return targetaccounthash.tohex();
    }
    public hash256 targetaccounthash() {
        return targetaccounthash;
    }

    public treeset<hash256> directorieswithindexesoutoforder() {
        treeset<hash256> ret = new treeset<hash256>();
        for (hash256 hash256 : directoriesmodifiedmorethanoncebytransaction) {
            directorynode dn = state.getdirectorynode(hash256);
            if (dn.owner() != null) {
                ret.add(hash256);
            }
        }
        return ret;
    }

    public boolean bad() {
        return !state.hash().equals(targetaccounthash);
    }

    public accountstate previousstate() {
        return previousstate;
    }
}
