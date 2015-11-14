package org.ripple.bouncycastle.pqc.crypto.gmss;

import java.util.enumeration;
import java.util.vector;

import org.ripple.bouncycastle.util.arrays;

class gmssutils
{
    static gmssleaf[] clone(gmssleaf[] data)
    {
        if (data == null)
        {
            return null;
        }
        gmssleaf[] copy = new gmssleaf[data.length];

        system.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    static gmssrootcalc[] clone(gmssrootcalc[] data)
    {
        if (data == null)
        {
            return null;
        }
        gmssrootcalc[] copy = new gmssrootcalc[data.length];

        system.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    static gmssrootsig[] clone(gmssrootsig[] data)
    {
        if (data == null)
        {
            return null;
        }
        gmssrootsig[] copy = new gmssrootsig[data.length];

        system.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    static byte[][] clone(byte[][] data)
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

    static byte[][][] clone(byte[][][] data)
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

    static treehash[] clone(treehash[] data)
    {
        if (data == null)
        {
            return null;
        }
        treehash[] copy = new treehash[data.length];

        system.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    static treehash[][] clone(treehash[][] data)
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

    static vector[] clone(vector[] data)
    {
        if (data == null)
        {
            return null;
        }
        vector[] copy = new vector[data.length];

        for (int i = 0; i != data.length; i++)
        {
            copy[i] = new vector();
            for (enumeration en = data[i].elements(); en.hasmoreelements();)
            {
                copy[i].addelement(en.nextelement());
            }
        }

        return copy;
    }

    static vector[][] clone(vector[][] data)
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
