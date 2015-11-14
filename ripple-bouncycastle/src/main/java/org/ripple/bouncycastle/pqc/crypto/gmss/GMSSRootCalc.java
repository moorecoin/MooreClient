package org.ripple.bouncycastle.pqc.crypto.gmss;

import java.util.enumeration;
import java.util.vector;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.integers;
import org.ripple.bouncycastle.util.encoders.hex;


/**
 * this class computes a whole merkle tree and saves the needed values for
 * authpath computation. it is used for precomputation of the root of a
 * following tree. after initialization, 2^h updates are required to complete
 * the root. every update requires one leaf value as parameter. while computing
 * the root all initial values for the authentication path algorithm (treehash,
 * auth, retain) are stored for later use.
 */
public class gmssrootcalc
{

    /**
     * max height of the tree
     */
    private int heightoftree;

    /**
     * length of the messagedigest
     */
    private int mdlength;

    /**
     * the treehash instances of the tree
     */
    private treehash[] treehash;

    /**
     * stores the retain nodes for authpath computation
     */
    private vector[] retain;

    /**
     * finally stores the root of the tree when finished
     */
    private byte[] root;

    /**
     * stores the authentication path y_1(i), i = 0..h-1
     */
    private byte[][] authpath;

    /**
     * the value k for the authentication path computation
     */
    private int k;

    /**
     * vector element that stores the nodes on the stack
     */
    private vector tailstack;

    /**
     * stores the height of all nodes laying on the tailstack
     */
    private vector heightofnodes;
    /**
     * the hash function used for the construction of the authentication trees
     */
    private digest messdigesttree;

    /**
     * an array of strings containing the name of the hash function used to
     * construct the authentication trees and used by the ots.
     */
    private gmssdigestprovider digestprovider;

    /**
     * stores the index of the current node on each height of the tree
     */
    private int[] index;

    /**
     * true if instance was already initialized, false otherwise
     */
    private boolean isinitialized;

    /**
     * true it instance was finished
     */
    private boolean isfinished;

    /**
     * integer that stores the index of the next seed that has to be omitted to
     * the treehashs
     */
    private int indexfornextseed;

    /**
     * temporary integer that stores the height of the next treehash instance
     * that gets initialized with a seed
     */
    private int heightofnextseed;

    /**
     * this constructor regenerates a prior treehash object
     *
     * @param digest     an array of strings, containing the digest of the used hash
     *                 function and prng and the digest of the corresponding
     *                 provider
     * @param statbyte status bytes
     * @param statint  status ints
     */
    public gmssrootcalc(digest digest, byte[][] statbyte, int[] statint,
                        treehash[] treeh, vector[] ret)
    {
        this.messdigesttree = digestprovider.get();
        this.digestprovider = digestprovider;
        // decode statint
        this.heightoftree = statint[0];
        this.mdlength = statint[1];
        this.k = statint[2];
        this.indexfornextseed = statint[3];
        this.heightofnextseed = statint[4];
        if (statint[5] == 1)
        {
            this.isfinished = true;
        }
        else
        {
            this.isfinished = false;
        }
        if (statint[6] == 1)
        {
            this.isinitialized = true;
        }
        else
        {
            this.isinitialized = false;
        }

        int taillength = statint[7];

        this.index = new int[heightoftree];
        for (int i = 0; i < heightoftree; i++)
        {
            this.index[i] = statint[8 + i];
        }

        this.heightofnodes = new vector();
        for (int i = 0; i < taillength; i++)
        {
            this.heightofnodes.addelement(integers.valueof(statint[8 + heightoftree
                + i]));
        }

        // decode statbyte
        this.root = statbyte[0];

        this.authpath = new byte[heightoftree][mdlength];
        for (int i = 0; i < heightoftree; i++)
        {
            this.authpath[i] = statbyte[1 + i];
        }

        this.tailstack = new vector();
        for (int i = 0; i < taillength; i++)
        {
            this.tailstack.addelement(statbyte[1 + heightoftree + i]);
        }

        // decode treeh
        this.treehash = gmssutils.clone(treeh);

        // decode ret
        this.retain = gmssutils.clone(ret);
    }

    /**
     * constructor
     *
     * @param heightoftree maximal height of the tree
     * @param digestprovider       an array of strings, containing the name of the used hash
     *                     function and prng and the name of the corresponding
     *                     provider
     */
    public gmssrootcalc(int heightoftree, int k, gmssdigestprovider digestprovider)
    {
        this.heightoftree = heightoftree;
        this.digestprovider = digestprovider;
        this.messdigesttree = digestprovider.get();
        this.mdlength = messdigesttree.getdigestsize();
        this.k = k;
        this.index = new int[heightoftree];
        this.authpath = new byte[heightoftree][mdlength];
        this.root = new byte[mdlength];
        // this.treehash = new treehash[this.heightoftree - this.k];
        this.retain = new vector[this.k - 1];
        for (int i = 0; i < k - 1; i++)
        {
            this.retain[i] = new vector();
        }

    }

    /**
     * initializes the calculation of a new root
     *
     * @param sharedstack the stack shared by all treehash instances of this tree
     */
    public void initialize(vector sharedstack)
    {
        this.treehash = new treehash[this.heightoftree - this.k];
        for (int i = 0; i < this.heightoftree - this.k; i++)
        {
            this.treehash[i] = new treehash(sharedstack, i, this.digestprovider.get());
        }

        this.index = new int[heightoftree];
        this.authpath = new byte[heightoftree][mdlength];
        this.root = new byte[mdlength];

        this.tailstack = new vector();
        this.heightofnodes = new vector();
        this.isinitialized = true;
        this.isfinished = false;

        for (int i = 0; i < heightoftree; i++)
        {
            this.index[i] = -1;
        }

        this.retain = new vector[this.k - 1];
        for (int i = 0; i < k - 1; i++)
        {
            this.retain[i] = new vector();
        }

        this.indexfornextseed = 3;
        this.heightofnextseed = 0;
    }

    /**
     * updates the root with one leaf and stores needed values in retain,
     * treehash or authpath. additionally counts the seeds used. this method is
     * used when performing the updates for tree++.
     *
     * @param seed the initial seed for treehash: seednext
     * @param leaf the height of the treehash
     */
    public void update(byte[] seed, byte[] leaf)
    {
        if (this.heightofnextseed < (this.heightoftree - this.k)
            && this.indexfornextseed - 2 == index[0])
        {
            this.initializetreehashseed(seed, this.heightofnextseed);
            this.heightofnextseed++;
            this.indexfornextseed *= 2;
        }
        // now call the simple update
        this.update(leaf);
    }

    /**
     * updates the root with one leaf and stores the needed values in retain,
     * treehash or authpath
     */
    public void update(byte[] leaf)
    {

        if (isfinished)
        {
            system.out.print("too much updates for tree!!");
            return;
        }
        if (!isinitialized)
        {
            system.err.println("gmssrootcalc not initialized!");
            return;
        }

        // a new leaf was omitted, so raise index on lowest layer
        index[0]++;

        // store the nodes on the lowest layer in treehash or authpath
        if (index[0] == 1)
        {
            system.arraycopy(leaf, 0, authpath[0], 0, mdlength);
        }
        else if (index[0] == 3)
        {
            // store in treehash only if k < h
            if (heightoftree > k)
            {
                treehash[0].setfirstnode(leaf);
            }
        }

        if ((index[0] - 3) % 2 == 0 && index[0] >= 3)
        {
            // store in retain if k = h
            if (heightoftree == k)
            // todo: check it
            {
                retain[0].insertelementat(leaf, 0);
            }
        }

        // if first update to this tree is made
        if (index[0] == 0)
        {
            tailstack.addelement(leaf);
            heightofnodes.addelement(integers.valueof(0));
        }
        else
        {

            byte[] help = new byte[mdlength];
            byte[] tobehashed = new byte[mdlength << 1];

            // store the new leaf in help
            system.arraycopy(leaf, 0, help, 0, mdlength);
            int helpheight = 0;
            // while top to nodes have same height
            while (tailstack.size() > 0
                && helpheight == ((integer)heightofnodes.lastelement())
                .intvalue())
            {

                // help <-- hash(stack top element || help)
                system.arraycopy(tailstack.lastelement(), 0, tobehashed, 0,
                    mdlength);
                tailstack.removeelementat(tailstack.size() - 1);
                heightofnodes.removeelementat(heightofnodes.size() - 1);
                system.arraycopy(help, 0, tobehashed, mdlength, mdlength);

                messdigesttree.update(tobehashed, 0, tobehashed.length);
                help = new byte[messdigesttree.getdigestsize()];
                messdigesttree.dofinal(help, 0);

                // the new help node is one step higher
                helpheight++;
                if (helpheight < heightoftree)
                {
                    index[helpheight]++;

                    // add index 1 element to initial authpath
                    if (index[helpheight] == 1)
                    {
                        system.arraycopy(help, 0, authpath[helpheight], 0,
                            mdlength);
                    }

                    if (helpheight >= heightoftree - k)
                    {
                        if (helpheight == 0)
                        {
                            system.out.println("m锟斤拷锟絇");
                        }
                        // add help element to retain stack if it is a right
                        // node
                        // and not stored in treehash
                        if ((index[helpheight] - 3) % 2 == 0
                            && index[helpheight] >= 3)
                        // todo: check it
                        {
                            retain[helpheight - (heightoftree - k)]
                                .insertelementat(help, 0);
                        }
                    }
                    else
                    {
                        // if element is third in his line add it to treehash
                        if (index[helpheight] == 3)
                        {
                            treehash[helpheight].setfirstnode(help);
                        }
                    }
                }
            }
            // push help element to the stack
            tailstack.addelement(help);
            heightofnodes.addelement(integers.valueof(helpheight));

            // is the root calculation finished?
            if (helpheight == heightoftree)
            {
                isfinished = true;
                isinitialized = false;
                root = (byte[])tailstack.lastelement();
            }
        }

    }

    /**
     * initializes the seeds for the treehashs of the tree precomputed by this
     * class
     *
     * @param seed  the initial seed for treehash: seednext
     * @param index the height of the treehash
     */
    public void initializetreehashseed(byte[] seed, int index)
    {
        treehash[index].initializeseed(seed);
    }

    /**
     * method to check whether the instance has been initialized or not
     *
     * @return true if treehash was already initialized
     */
    public boolean wasinitialized()
    {
        return isinitialized;
    }

    /**
     * method to check whether the instance has been finished or not
     *
     * @return true if tree has reached its maximum height
     */
    public boolean wasfinished()
    {
        return isfinished;
    }

    /**
     * returns the authentication path of the first leaf of the tree
     *
     * @return the authentication path of the first leaf of the tree
     */
    public byte[][] getauthpath()
    {
        return gmssutils.clone(authpath);
    }

    /**
     * returns the initial treehash instances, storing value y_3(i)
     *
     * @return the initial treehash instances, storing value y_3(i)
     */
    public treehash[] gettreehash()
    {
        return gmssutils.clone(treehash);
    }

    /**
     * returns the retain stacks storing all right nodes near to the root
     *
     * @return the retain stacks storing all right nodes near to the root
     */
    public vector[] getretain()
    {
        return gmssutils.clone(retain);
    }

    /**
     * returns the finished root value
     *
     * @return the finished root value
     */
    public byte[] getroot()
    {
        return arrays.clone(root);
    }

    /**
     * returns the shared stack
     *
     * @return the shared stack
     */
    public vector getstack()
    {
        vector copy = new vector();
        for (enumeration en = tailstack.elements(); en.hasmoreelements();)
        {
            copy.addelement(en.nextelement());
        }
        return copy;
    }

    /**
     * returns the status byte array used by the gmssprivatekeyasn.1 class
     *
     * @return the status bytes
     */
    public byte[][] getstatbyte()
    {

        int taillength;
        if (tailstack == null)
        {
            taillength = 0;
        }
        else
        {
            taillength = tailstack.size();
        }
        byte[][] statbyte = new byte[1 + heightoftree + taillength][64]; //fixme: messdigesttree.getbytelength()
        statbyte[0] = root;

        for (int i = 0; i < heightoftree; i++)
        {
            statbyte[1 + i] = authpath[i];
        }
        for (int i = 0; i < taillength; i++)
        {
            statbyte[1 + heightoftree + i] = (byte[])tailstack.elementat(i);
        }

        return statbyte;
    }

    /**
     * returns the status int array used by the gmssprivatekeyasn.1 class
     *
     * @return the status ints
     */
    public int[] getstatint()
    {

        int taillength;
        if (tailstack == null)
        {
            taillength = 0;
        }
        else
        {
            taillength = tailstack.size();
        }
        int[] statint = new int[8 + heightoftree + taillength];
        statint[0] = heightoftree;
        statint[1] = mdlength;
        statint[2] = k;
        statint[3] = indexfornextseed;
        statint[4] = heightofnextseed;
        if (isfinished)
        {
            statint[5] = 1;
        }
        else
        {
            statint[5] = 0;
        }
        if (isinitialized)
        {
            statint[6] = 1;
        }
        else
        {
            statint[6] = 0;
        }
        statint[7] = taillength;

        for (int i = 0; i < heightoftree; i++)
        {
            statint[8 + i] = index[i];
        }
        for (int i = 0; i < taillength; i++)
        {
            statint[8 + heightoftree + i] = ((integer)heightofnodes
                .elementat(i)).intvalue();
        }

        return statint;
    }

    /**
     * @return a human readable version of the structure
     */
    public string tostring()
    {
        string out = "";
        int taillength;
        if (tailstack == null)
        {
            taillength = 0;
        }
        else
        {
            taillength = tailstack.size();
        }

        for (int i = 0; i < 8 + heightoftree + taillength; i++)
        {
            out = out + getstatint()[i] + " ";
        }
        for (int i = 0; i < 1 + heightoftree + taillength; i++)
        {
            out = out + new string(hex.encode(getstatbyte()[i])) + " ";
        }
        out = out + "  " + digestprovider.get().getdigestsize();
        return out;
    }
}
