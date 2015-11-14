package org.moorecoinlab.core.types.shamap;


import org.moorecoinlab.core.hash.hash256;

import java.util.treeset;

public class shamapdiff {
    public shamap one, two;

    public treeset<hash256> modified = new treeset<hash256>();
    public treeset<hash256> deleted = new treeset<hash256>();
    public treeset<hash256> added = new treeset<hash256>();

    public shamapdiff(shamap one, shamap two) {
        this.one = one;
        this.two = two;
    }

    public void find() {
        one.hash();
        two.hash();
        compare(one, two);
    }

    public void apply(shamap sa) {
        for (hash256 mod : modified) {
            boolean modded = sa.updateitem(mod, two.getitem(mod).copy());
            if (!modded) throw new assertionerror();
        }

        for (hash256 add : added) {
            boolean added = sa.additem(add, two.getitem(add).copy());
            if (!added) throw new assertionerror();
        }
        for (hash256 delete : deleted) {
            boolean removed = sa.removeleaf(delete);
            if (!removed) throw new assertionerror();
        }
    }
    private void compare(shamapinner a, shamapinner b) {
        for (int i = 0; i < 16; i++) {
            shamapnode achild = a.getbranch(i);
            shamapnode bchild = b.getbranch(i);

            if (achild == null && bchild != null) {
                trackadded(bchild);
                // added in b
            } else if (achild != null && bchild == null) {
                trackremoved(achild);
                // removed from b
            } else if (achild != null && !achild.hash().equals(bchild.hash())) {
                boolean aleaf  = achild.isleaf(),
                        bleaf  = bchild.isleaf();

                if (aleaf && bleaf) {
                    shamapleaf la = (shamapleaf) achild;
                    shamapleaf lb = (shamapleaf) bchild;
                    if (la.index.equals(lb.index)) {
                        modified.add(la.index);
                    } else {
                        deleted.add(la.index);
                        added.add(lb.index);
                    }
                } else if (aleaf /*&& binner*/) {
                    shamapleaf la = (shamapleaf) achild;
                    shamapinner ib = (shamapinner) bchild;
                    trackadded(ib);

                    if (ib.hasleaf(la.index)) {
                        // because trackadded would have added it
                        added.remove(la.index);
                        shamapleaf leaf = ib.getleaf(la.index);
                        if (!leaf.hash().equals(la.hash())) {
                            modified.add(la.index);
                        }
                    } else {
                        deleted.add(la.index);
                    }
                } else if (bleaf /*&& ainner*/) {
                    shamapleaf lb = (shamapleaf) bchild;
                    shamapinner ia = (shamapinner) achild;
                    trackremoved(ia);

                    if (ia.hasleaf(lb.index)) {
                        // because trackremoved would have deleted it
                        deleted.remove(lb.index);
                        shamapleaf leaf = ia.getleaf(lb.index);
                        if (!leaf.hash().equals(lb.hash())) {
                            modified.add(lb.index);
                        }
                    } else {
                        added.add(lb.index);
                    }
                } else /*if (ainner && binner)*/ {
                    compare((shamapinner) achild, (shamapinner) bchild);
                }
            }
        }
    }
    private void trackremoved(shamapnode child) {
        child.walkanyleaves(new leafwalker() {
            @override
            public void onleaf(shamapleaf leaf) {
                deleted.add(leaf.index);
            }
        });
    }
    private void trackadded(shamapnode child) {
        child.walkanyleaves(new leafwalker() {
            @override
            public void onleaf(shamapleaf leaf) {
                added.add(leaf.index);
            }
        });
    }
}
