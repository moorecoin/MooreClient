package org.moorecoinlab.core.types.shamap;

public interface treewalker {
    public void onleaf(shamapleaf leaf);
    public void oninner(shamapinner inner);
}
