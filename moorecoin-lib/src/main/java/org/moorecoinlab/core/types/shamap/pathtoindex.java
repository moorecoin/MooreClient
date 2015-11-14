package org.moorecoinlab.core.types.shamap;


import org.moorecoinlab.core.hash.hash256;

import java.util.arraydeque;
import java.util.iterator;

public class pathtoindex {
    public hash256 index;
    public shamapleaf leaf;

    private arraydeque<shamapinner> inners;
    private shamapinner[] dirtied;
    private boolean matched = false;

    public boolean hasleaf() {
        return leaf != null;
    }
    public boolean leafmatchedindex() {
        return matched;
    }
    public boolean copyleafonupdate() {
        return leaf.version != dirtied[0].version;
    }

    public shamapinner top() {
        return dirtied[dirtied.length - 1];
    }

    // returns the
    public shamapinner dirtyorcopyinners() {
        if (maybecopyonwrite()) {
            int ix = 0;
            // we want to make a uniformly accessed array of the inners
            dirtied = new shamapinner[inners.size()];
            // from depth 0 to 1, to 2, to 3, don't be fooled by the api
            iterator<shamapinner> it = inners.descendingiterator();

            // this is actually the root which could be the top of the stack
            // think about it ;)
            shamapinner top = it.next();
            dirtied[ix++] = top;
            top.invalidate();

            while (it.hasnext()) {
                shamapinner next = it.next();
                boolean docopies = next.version != top.version;

                if (docopies) {
                    shamapinner copy = next.copy(top.version);
                    copy.invalidate();
                    top.setbranch(index, copy);
                    next = copy;
                } else {
                    next.invalidate();
                }
                top = next;
                dirtied[ix++] = top;
            }
            return top;
        } else {
            copyinnerstodirtiedarray();
            return inners.peekfirst();
        }
    }

    public boolean hasmatchedleaf() {
        return hasleaf() && leafmatchedindex();
    }

    public void collapseonlyleafchildinners() {
        assert dirtied != null;

        shamapinner next;
        shamapleaf onlychild = null;

        for (int i = dirtied.length - 1; i >= 0; i--) {
            next = dirtied[i];
            if (onlychild != null) {
                next.setleaf(onlychild);
            }
            onlychild = next.onlychildleaf();
            if (onlychild == null) {
                break;
            }
        }
    }

    private void copyinnerstodirtiedarray() {
        int ix = 0;
        dirtied = new shamapinner[inners.size()];
        iterator<shamapinner> descending = inners.descendingiterator();
        while (descending.hasnext()) {
            shamapinner next = descending.next();
            dirtied[ix++] = next;
            next.invalidate();
        }
    }

    private boolean maybecopyonwrite() {
        return inners.peeklast().docow;
    }

    public pathtoindex(shamapinner root, hash256 index) {
        this.index = index;
        makestack(root, index);
    }

    private void makestack(shamapinner root, hash256 index) {
        inners = new arraydeque<shamapinner>();
        shamapinner top = root;

        while (true) {
            inners.push(top);
            shamapnode existing = top.getbranch(index);
            if (existing == null) {
                break;
            } else if (existing.isleaf()) {
                leaf = existing.asleaf();
                matched = leaf.index.equals(index);
                break;
            }
            else if (existing.isinner()) {
                top = existing.asinner();
            }
        }
    }

    public shamapleaf invalidatedpossiblycopiedleafforupdating() {
        assert matched;
        if (dirtied == null) {
            dirtyorcopyinners();
        }
        shamapleaf theleaf = leaf;

        if (copyleafonupdate()) {
            theleaf = leaf.copy();
            top().setleaf(theleaf);
        }
        theleaf.invalidate();
        return theleaf;
    }
}
