package org.ripple.bouncycastle.pqc.jcajce.spec;

import java.security.spec.keyspec;
import java.util.vector;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.pqc.crypto.gmss.gmssleaf;
import org.ripple.bouncycastle.pqc.crypto.gmss.gmssparameters;
import org.ripple.bouncycastle.pqc.crypto.gmss.gmssrootcalc;
import org.ripple.bouncycastle.pqc.crypto.gmss.gmssrootsig;
import org.ripple.bouncycastle.pqc.crypto.gmss.treehash;
import org.ripple.bouncycastle.util.arrays;


/**
 * this class provides a specification for a gmss private key.
 */
public class gmssprivatekeyspec
    implements keyspec
{

    private int[] index;

    private byte[][] currentseed;
    private byte[][] nextnextseed;

    private byte[][][] currentauthpath;
    private byte[][][] nextauthpath;

    private treehash[][] currenttreehash;
    private treehash[][] nexttreehash;

    private vector[] currentstack;
    private vector[] nextstack;

    private vector[][] currentretain;
    private vector[][] nextretain;

    private byte[][][] keep;

    private gmssleaf[] nextnextleaf;
    private gmssleaf[] upperleaf;
    private gmssleaf[] uppertreehashleaf;

    private int[] mintreehash;

    private gmssparameters gmssps;

    private byte[][] nextroot;
    private gmssrootcalc[] nextnextroot;

    private byte[][] currentrootsig;
    private gmssrootsig[] nextrootsig;

    /**
     * @param index             tree indices
     * @param currentseed       seed for the generation of private ots keys for the
     *                          current subtrees (tree)
     * @param nextnextseed      seed for the generation of private ots keys for the
     *                          subtrees after next (tree++)
     * @param currentauthpath   array of current authentication paths (authpath)
     * @param nextauthpath      array of next authentication paths (authpath+)
     * @param keep              keep array for the authpath algorithm
     * @param currenttreehash   treehash for authpath algorithm of current tree
     * @param nexttreehash      treehash for authpath algorithm of next tree (tree+)
     * @param currentstack      shared stack for authpath algorithm of current tree
     * @param nextstack         shared stack for authpath algorithm of next tree (tree+)
     * @param currentretain     retain stack for authpath algorithm of current tree
     * @param nextretain        retain stack for authpath algorithm of next tree (tree+)
     * @param nextnextleaf      array of upcoming leafs of the tree after next (leaf++) of
     *                          each layer
     * @param upperleaf         needed for precomputation of upper nodes
     * @param uppertreehashleaf needed for precomputation of upper treehash nodes
     * @param mintreehash       index of next treehash instance to receive an update
     * @param nextroot          the roots of the next trees (root+)
     * @param nextnextroot      the roots of the tree after next (root++)
     * @param currentrootsig    array of signatures of the roots of the current subtrees
     *                          (sig)
     * @param nextrootsig       array of signatures of the roots of the next subtree
     *                          (sig+)
     * @param gmssparameterset  the gmss parameterset
     */
    public gmssprivatekeyspec(int[] index, byte[][] currentseed,
                              byte[][] nextnextseed, byte[][][] currentauthpath,
                              byte[][][] nextauthpath, treehash[][] currenttreehash,
                              treehash[][] nexttreehash, vector[] currentstack,
                              vector[] nextstack, vector[][] currentretain,
                              vector[][] nextretain, byte[][][] keep, gmssleaf[] nextnextleaf,
                              gmssleaf[] upperleaf, gmssleaf[] uppertreehashleaf,
                              int[] mintreehash, byte[][] nextroot, gmssrootcalc[] nextnextroot,
                              byte[][] currentrootsig, gmssrootsig[] nextrootsig,
                              gmssparameters gmssparameterset)
    {
        this.index = index;
        this.currentseed = currentseed;
        this.nextnextseed = nextnextseed;
        this.currentauthpath = currentauthpath;
        this.nextauthpath = nextauthpath;
        this.currenttreehash = currenttreehash;
        this.nexttreehash = nexttreehash;
        this.currentstack = currentstack;
        this.nextstack = nextstack;
        this.currentretain = currentretain;
        this.nextretain = nextretain;
        this.keep = keep;
        this.nextnextleaf = nextnextleaf;
        this.upperleaf = upperleaf;
        this.uppertreehashleaf = uppertreehashleaf;
        this.mintreehash = mintreehash;
        this.nextroot = nextroot;
        this.nextnextroot = nextnextroot;
        this.currentrootsig = currentrootsig;
        this.nextrootsig = nextrootsig;
        this.gmssps = gmssparameterset;
    }

    public int[] getindex()
    {
        return arrays.clone(index);
    }

    public byte[][] getcurrentseed()
    {
        return clone(currentseed);
    }

    public byte[][] getnextnextseed()
    {
        return clone(nextnextseed);
    }

    public byte[][][] getcurrentauthpath()
    {
        return clone(currentauthpath);
    }

    public byte[][][] getnextauthpath()
    {
        return clone(nextauthpath);
    }

    public treehash[][] getcurrenttreehash()
    {
        return clone(currenttreehash);
    }

    public treehash[][] getnexttreehash()
    {
        return clone(nexttreehash);
    }

    public byte[][][] getkeep()
    {
        return clone(keep);
    }

    public vector[] getcurrentstack()
    {
        return clone(currentstack);
    }

    public vector[] getnextstack()
    {
        return clone(nextstack);
    }

    public vector[][] getcurrentretain()
    {
        return clone(currentretain);
    }

    public vector[][] getnextretain()
    {
        return clone(nextretain);
    }

    public gmssleaf[] getnextnextleaf()
    {
        return clone(nextnextleaf);
    }

    public gmssleaf[] getupperleaf()
    {
        return clone(upperleaf);
    }

    public gmssleaf[] getuppertreehashleaf()
    {
        return clone(uppertreehashleaf);
    }

    public int[] getmintreehash()
    {
        return arrays.clone(mintreehash);
    }

    public gmssrootsig[] getnextrootsig()
    {
        return clone(nextrootsig);
    }

    public gmssparameters getgmssps()
    {
        return gmssps;
    }

    public byte[][] getnextroot()
    {
        return clone(nextroot);
    }

    public gmssrootcalc[] getnextnextroot()
    {
        return clone(nextnextroot);
    }

    public byte[][] getcurrentrootsig()
    {
        return clone(currentrootsig);
    }

    private static gmssleaf[] clone(gmssleaf[] data)
    {
        if (data == null)
        {
            return null;
        }
        gmssleaf[] copy = new gmssleaf[data.length];

        system.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    private static gmssrootcalc[] clone(gmssrootcalc[] data)
    {
        if (data == null)
        {
            return null;
        }
        gmssrootcalc[] copy = new gmssrootcalc[data.length];

        system.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    private static gmssrootsig[] clone(gmssrootsig[] data)
    {
        if (data == null)
        {
            return null;
        }
        gmssrootsig[] copy = new gmssrootsig[data.length];

        system.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    private static byte[][] clone(byte[][] data)
    {
        if (data == null)
        {
            return null;
        }
        byte[][] copy = new byte[data.length][];

        for (int i = 0; i != data.length; i++)
        {
            copy[i] = arrays.clone(data[i]);
        }

        return copy;
    }

    private static byte[][][] clone(byte[][][] data)
    {
        if (data == null)
        {
            return null;
        }
        byte[][][] copy = new byte[data.length][][];

        for (int i = 0; i != data.length; i++)
        {
            copy[i] = clone(data[i]);
        }

        return copy;
    }

    private static treehash[] clone(treehash[] data)
    {
        if (data == null)
        {
            return null;
        }
        treehash[] copy = new treehash[data.length];

        system.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    private static treehash[][] clone(treehash[][] data)
    {
        if (data == null)
        {
            return null;
        }
        treehash[][] copy = new treehash[data.length][];

        for (int i = 0; i != data.length; i++)
        {
            copy[i] = clone(data[i]);
        }

        return copy;
    }

    private static vector[] clone(vector[] data)
    {
        if (data == null)
        {
            return null;
        }
        vector[] copy = new vector[data.length];

        for (int i = 0; i != data.length; i++)
        {
            copy[i] = new vector(data[i]);
        }

        return copy;
    }

    private static vector[][] clone(vector[][] data)
    {
        if (data == null)
        {
            return null;
        }
        vector[][] copy = new vector[data.length][];

        for (int i = 0; i != data.length; i++)
        {
            copy[i] = clone(data[i]);
        }

        return copy;
    }
}