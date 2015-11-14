package org.moorecoinlab.core.types.shamap;


import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.hash.prefixes.hashprefix;
import org.moorecoinlab.core.hash.prefixes.prefix;
import org.moorecoinlab.core.serialized.bytessink;

import java.util.iterator;

public class shamapinner extends shamapnode implements iterable<shamapnode> {
    public int depth;
    int slotbits = 0;
    int version = 0;
    boolean docow;
    protected shamapnode[] branches = new shamapnode[16];

    public shamapinner(int depth) {
        this(false, depth, 0);
    }

    public shamapinner(boolean iscopy, int depth, int version) {
        this.docow = iscopy;
        this.depth = depth;
        this.version = version;
    }

    protected shamapinner copy(int version) {
        shamapinner copy = makeinnerofsameclass(depth);
        system.arraycopy(branches, 0, copy.branches, 0, branches.length);
        copy.slotbits = slotbits;
        copy.hash = hash;
        copy.version = version;
        docow = true;

        return copy;
    }

    protected shamapinner makeinnerofsameclass(int depth) {
        return new shamapinner(true, depth, version);
    }

    protected shamapinner makeinnerchild() {
        int childdepth = depth + 1;
        if (childdepth >= 64) throw new assertionerror();
        return new shamapinner(docow, childdepth, version);
    }

    // descend into the tree, find the leaf matching this index
    // and if the tree has it.
    protected void setleaf(shamapleaf leaf) {
        if (leaf.version == -1) {
            leaf.version = version;
        }
        setbranch(leaf.index, leaf);
    }

    private void removebranch(hash256 index) {
        removebranch(selectbranch(index));
    }

    public void walkleaves(leafwalker leafwalker) {
        for (shamapnode branch : branches) {
            if (branch != null) {
                if (branch.isinner()) {
                    branch.asinner().walkleaves(leafwalker);
                } else if (branch.isleaf()) {
                    leafwalker.onleaf(branch.asleaf());
                }
            }
        }
    }

    public void walktree(treewalker treewalker) {
        treewalker.oninner(this);
        for (shamapnode branch : branches) {
            if (branch != null) {
                if (branch.isleaf()) {
                    shamapleaf ln = branch.asleaf();
                    treewalker.onleaf(ln);
                } else if (branch.isinner()) {
                    shamapinner childinner = branch.asinner();
                    childinner.walktree(treewalker);
                }
            }
        }

    }

    public void walkhashedtree(hashedtreewalker walker) {
        walker.oninner(hash(), this);

        for (shamapnode branch : branches) {
            if (branch != null) {
                if (branch.isleaf()) {
                    shamapleaf ln = branch.asleaf();
                    walker.onleaf(branch.hash(), ln);
                } else if (branch.isinner()) {
                    shamapinner childinner = branch.asinner();
                    childinner.walkhashedtree(walker);
                }
            }
        }
    }

    /**
     * @return the `only child` leaf or null if other children
     */
    public shamapleaf onlychildleaf() {
        shamapleaf leaf = null;
        int leaves = 0;

        for (shamapnode branch : branches) {
            if (branch != null) {
                if (branch.isinner()) {
                    leaf = null;
                    break;
                } else if (++leaves == 1) {
                    leaf = branch.asleaf();
                } else {
                    leaf = null;
                    break;
                }
            }
        }
        return leaf;
    }

    public boolean removeleaf(hash256 index) {
        pathtoindex path = pathtoindex(index);
        if (path.hasmatchedleaf()) {
            shamapinner top = path.dirtyorcopyinners();
            top.removebranch(index);
            path.collapseonlyleafchildinners();
            return true;
        } else {
            return false;
        }
    }

    public shamapitem getitem(hash256 index) {
        shamapleaf leaf = getleaf(index);
        return leaf == null ? null : leaf.item;
    }

    public boolean additem(hash256 index, shamapitem item) {
        return addleaf(new shamapleaf(index, item));
    }

    public boolean updateitem(hash256 index, shamapitem item) {
        return updateleaf(new shamapleaf(index, item));
    }

    public boolean hasleaf(hash256 index) {
        return pathtoindex(index).hasmatchedleaf();
    }

    public shamapleaf getleaf(hash256 index) {
        pathtoindex stack = pathtoindex(index);
        if (stack.hasmatchedleaf()) {
            return stack.leaf;
        } else {
            return null;
        }
    }

    public boolean addleaf(shamapleaf leaf) {
        pathtoindex stack = pathtoindex(leaf.index);
        if (stack.hasmatchedleaf()) {
            return false;
        } else {
            shamapinner top = stack.dirtyorcopyinners();
            top.addleaftoterminalinner(leaf);
            return true;
        }
    }

    public boolean updateleaf(shamapleaf leaf) {
        pathtoindex stack = pathtoindex(leaf.index);
        if (stack.hasmatchedleaf()) {
            shamapinner top = stack.dirtyorcopyinners();
            // why not update in place? because of structural sharing
            top.setleaf(leaf);
            return true;
        } else {
            return false;
        }
    }

    public pathtoindex pathtoindex(hash256 index) {
        return new pathtoindex(this, index);
    }

    /**
     * this should only be called on the deepest inners, as it
     * does not do any dirtying.
     * @param leaf to add to inner
     */
    void addleaftoterminalinner(shamapleaf leaf) {
        shamapnode branch = getbranch(leaf.index);
        if (branch == null) {
            setleaf(leaf);
        } else if (branch.isinner()) {
            // this should never be called
            throw new assertionerror();
        } else if (branch.isleaf()) {
            shamapinner inner = makeinnerchild();
            setbranch(leaf.index, inner);
            inner.addleaftoterminalinner(leaf);
            inner.addleaftoterminalinner(branch.asleaf());
        }
    }

    protected void setbranch(hash256 index, shamapnode node) {
        setbranch(selectbranch(index), node);
    }

    protected shamapnode getbranch(hash256 index) {
        return getbranch(index.nibblet(depth));
    }

    public shamapnode getbranch(int i) {
        return branches[i];
    }

    public shamapnode branch(int i) {
        return branches[i];
    }

    protected int selectbranch(hash256 index) {
        return index.nibblet(depth);
    }

    public boolean hasleaf(int i) {
        return branches[i].isleaf();
    }
    public boolean hasinner(int i) {
        return branches[i].isinner();
    }
    public boolean hasnone(int i) {return branches[i] == null;}

    private void setbranch(int slot, shamapnode node) {
        slotbits = slotbits | (1 << slot);
        branches[slot] = node;
        invalidate();
    }

    private void removebranch(int slot) {
        branches[slot] = null;
        slotbits = slotbits & ~(1 << slot);
    }
    public boolean empty() {
        return slotbits == 0;
    }

    @override public boolean isleaf() { return false; }
    @override public boolean isinner() { return true; }

    @override
    prefix hashprefix() {
        return hashprefix.innernode;
    }

    @override
    public void tobytessink(bytessink sink) {
        for (shamapnode branch : branches) {
            if (branch != null) {
                branch.hash().tobytessink(sink);
            } else {
                hash256.zero_256.tobytessink(sink);
            }
        }
    }

    @override
    public hash256 hash() {
        if (empty()) {
            // empty inners have a hash of all zero
            // it's only valid for a root node to be empty
            // any other inner node, must contain at least a
            // single leaf
            assert depth == 0;
            return hash256.zero_256;
        } else {
            // hash the hashprefix() and tobytessink
            return super.hash();
        }
    }

    public shamapleaf getleafforupdating(hash256 leaf) {
        pathtoindex path = pathtoindex(leaf);
        if (path.hasmatchedleaf()) {
            return path.invalidatedpossiblycopiedleafforupdating();
        }
        return null;
    }

    @override
    public iterator<shamapnode> iterator() {
        return new iterator<shamapnode>() {
            int ix = 0;

            @override
            public boolean hasnext() {
                return ix != 16;
            }

            @override
            public shamapnode next() {
                return branch(ix++);
            }

            @override
            public void remove() {
                throw new unsupportedoperationexception();
            }
        };
    }
}
