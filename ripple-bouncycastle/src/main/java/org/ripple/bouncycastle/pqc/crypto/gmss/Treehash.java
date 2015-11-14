package org.ripple.bouncycastle.pqc.crypto.gmss;

import java.util.vector;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.pqc.crypto.gmss.util.gmssrandom;
import org.ripple.bouncycastle.util.integers;
import org.ripple.bouncycastle.util.encoders.hex;


/**
 * this class implements a treehash instance for the merkle tree traversal
 * algorithm. the first node of the stack is stored in this instance itself,
 * additional tail nodes are stored on a tailstack.
 */
public class treehash
{

    /**
     * max height of current treehash instance.
     */
    private int maxheight;

    /**
     * vector element that stores the nodes on the stack
     */
    private vector tailstack;

    /**
     * vector element that stores the height of the nodes on the stack
     */
    private vector heightofnodes;

    /**
     * the first node is stored in the treehash instance itself, not on stack
     */
    private byte[] firstnode;

    /**
     * seedactive needed for the actual node
     */
    private byte[] seedactive;

    /**
     * the seed needed for the next re-initialization of the treehash instance
     */
    private byte[] seednext;

    /**
     * number of nodes stored on the stack and belonging to this treehash
     * instance
     */
    private int taillength;

    /**
     * the height in the tree of the first node stored in treehash
     */
    private int firstnodeheight;

    /**
     * true if treehash instance was already initialized, false otherwise
     */
    private boolean isinitialized;

    /**
     * true if the first node's height equals the maxheight of the treehash
     */
    private boolean isfinished;

    /**
     * true if the nextseed has been initialized with index 3*2^h needed for the
     * seed scheduling
     */
    private boolean seedinitialized;

    /**
     * denotes the message digest used by the tree to create nodes
     */
    private digest messdigesttree;

    /**
     * this constructor regenerates a prior treehash object
     *
     * @param name     an array of strings, containing the name of the used hash
     *                 function and prng and the name of the corresponding provider
     * @param statbyte status bytes
     * @param statint  status ints
     */
    public treehash(digest name, byte[][] statbyte, int[] statint)
    {
        this.messdigesttree = name;

        // decode statint
        this.maxheight = statint[0];
        this.taillength = statint[1];
        this.firstnodeheight = statint[2];

        if (statint[3] == 1)
        {
            this.isfinished = true;
        }
        else
        {
            this.isfinished = false;
        }
        if (statint[4] == 1)
        {
            this.isinitialized = true;
        }
        else
        {
            this.isinitialized = false;
        }
        if (statint[5] == 1)
        {
            this.seedinitialized = true;
        }
        else
        {
            this.seedinitialized = false;
        }

        this.heightofnodes = new vector();
        for (int i = 0; i < taillength; i++)
        {
            this.heightofnodes.addelement(integers.valueof(statint[6 + i]));
        }

        // decode statbyte
        this.firstnode = statbyte[0];
        this.seedactive = statbyte[1];
        this.seednext = statbyte[2];

        this.tailstack = new vector();
        for (int i = 0; i < taillength; i++)
        {
            this.tailstack.addelement(statbyte[3 + i]);
        }
    }

    /**
     * constructor
     *
     * @param tailstack a vector element where the stack nodes are stored
     * @param maxheight maximal height of the treehash instance
     * @param digest    an array of strings, containing the name of the used hash
     *                  function and prng and the name of the corresponding provider
     */
    public treehash(vector tailstack, int maxheight, digest digest)
    {
        this.tailstack = tailstack;
        this.maxheight = maxheight;
        this.firstnode = null;
        this.isinitialized = false;
        this.isfinished = false;
        this.seedinitialized = false;
        this.messdigesttree = digest;

        this.seednext = new byte[messdigesttree.getdigestsize()];
        this.seedactive = new byte[messdigesttree.getdigestsize()];
    }

    /**
     * method to initialize the seeds needed for the precomputation of right
     * nodes. should be initialized with index 3*2^i for treehash_i
     *
     * @param seedin
     */
    public void initializeseed(byte[] seedin)
    {
        system.arraycopy(seedin, 0, this.seednext, 0, this.messdigesttree
            .getdigestsize());
        this.seedinitialized = true;
    }

    /**
     * initializes the treehash instance. the seeds must already have been
     * initialized to work correctly.
     */
    public void initialize()
    {
        if (!this.seedinitialized)
        {
            system.err.println("seed " + this.maxheight + " not initialized");
            return;
        }

        this.heightofnodes = new vector();
        this.taillength = 0;
        this.firstnode = null;
        this.firstnodeheight = -1;
        this.isinitialized = true;
        system.arraycopy(this.seednext, 0, this.seedactive, 0, messdigesttree
            .getdigestsize());
    }

    /**
     * calculates one update of the treehash instance, i.e. creates a new leaf
     * and hashes if possible
     *
     * @param gmssrandom an instance of the prng
     * @param leaf       the byte value of the leaf needed for the update
     */
    public void update(gmssrandom gmssrandom, byte[] leaf)
    {

        if (this.isfinished)
        {
            system.err
                .println("no more update possible for treehash instance!");
            return;
        }
        if (!this.isinitialized)
        {
            system.err
                .println("treehash instance not initialized before update");
            return;
        }

        byte[] help = new byte[this.messdigesttree.getdigestsize()];
        int helpheight = -1;

        gmssrandom.nextseed(this.seedactive);

        // if treehash gets first update
        if (this.firstnode == null)
        {
            this.firstnode = leaf;
            this.firstnodeheight = 0;
        }
        else
        {
            // store the new node in help array, do not push it on the stack
            help = leaf;
            helpheight = 0;

            // hash the nodes on the stack if possible
            while (this.taillength > 0
                && helpheight == ((integer)heightofnodes.lastelement())
                .intvalue())
            {
                // put top element of the stack and help node in array
                // 'tobehashed'
                // and hash them together, put result again in help array
                byte[] tobehashed = new byte[this.messdigesttree
                    .getdigestsize() << 1];

                // pop element from stack
                system.arraycopy(this.tailstack.lastelement(), 0, tobehashed,
                    0, this.messdigesttree.getdigestsize());
                this.tailstack.removeelementat(this.tailstack.size() - 1);
                this.heightofnodes
                    .removeelementat(this.heightofnodes.size() - 1);

                system.arraycopy(help, 0, tobehashed, this.messdigesttree
                    .getdigestsize(), this.messdigesttree
                    .getdigestsize());
                messdigesttree.update(tobehashed, 0, tobehashed.length);
                help = new byte[messdigesttree.getdigestsize()];
                messdigesttree.dofinal(help, 0);

                // increase help height, stack was reduced by one element
                helpheight++;
                this.taillength--;
            }

            // push the new node on the stack
            this.tailstack.addelement(help);
            this.heightofnodes.addelement(integers.valueof(helpheight));
            this.taillength++;

            // finally check whether the top node on stack and the first node
            // in treehash have same height. if so hash them together
            // and store them in treehash
            if (((integer)heightofnodes.lastelement()).intvalue() == this.firstnodeheight)
            {
                byte[] tobehashed = new byte[this.messdigesttree
                    .getdigestsize() << 1];
                system.arraycopy(this.firstnode, 0, tobehashed, 0,
                    this.messdigesttree.getdigestsize());

                // pop element from tailstack and copy it into help2 array
                system.arraycopy(this.tailstack.lastelement(), 0, tobehashed,
                    this.messdigesttree.getdigestsize(),
                    this.messdigesttree.getdigestsize());
                this.tailstack.removeelementat(this.tailstack.size() - 1);
                this.heightofnodes
                    .removeelementat(this.heightofnodes.size() - 1);

                // store new element in firstnode, stack is then empty
                messdigesttree.update(tobehashed, 0, tobehashed.length);
                this.firstnode = new byte[messdigesttree.getdigestsize()];
                messdigesttree.dofinal(this.firstnode, 0);
                this.firstnodeheight++;

                // empty the stack
                this.taillength = 0;
            }
        }

        // check if treehash instance is completed
        if (this.firstnodeheight == this.maxheight)
        {
            this.isfinished = true;
        }
    }

    /**
     * destroys a treehash instance after the top node was taken for
     * authentication path.
     */
    public void destroy()
    {
        this.isinitialized = false;
        this.isfinished = false;
        this.firstnode = null;
        this.taillength = 0;
        this.firstnodeheight = -1;
    }

    /**
     * returns the height of the lowest node stored either in treehash or on the
     * stack. it must not be set to infinity (as mentioned in the paper) because
     * this cases are considered in the computeauthpaths method of
     * jdkgmssprivatekey
     *
     * @return height of the lowest node
     */
    public int getlowestnodeheight()
    {
        if (this.firstnode == null)
        {
            return this.maxheight;
        }
        else if (this.taillength == 0)
        {
            return this.firstnodeheight;
        }
        else
        {
            return math.min(this.firstnodeheight, ((integer)heightofnodes
                .lastelement()).intvalue());
        }
    }

    /**
     * returns the top node height
     *
     * @return height of the first node, the top node
     */
    public int getfirstnodeheight()
    {
        if (firstnode == null)
        {
            return maxheight;
        }
        return firstnodeheight;
    }

    /**
     * method to check whether the instance has been initialized or not
     *
     * @return true if treehash was already initialized
     */
    public boolean wasinitialized()
    {
        return this.isinitialized;
    }

    /**
     * method to check whether the instance has been finished or not
     *
     * @return true if treehash has reached its maximum height
     */
    public boolean wasfinished()
    {
        return this.isfinished;
    }

    /**
     * returns the first node stored in treehash instance itself
     *
     * @return the first node stored in treehash instance itself
     */
    public byte[] getfirstnode()
    {
        return this.firstnode;
    }

    /**
     * returns the active seed
     *
     * @return the active seed
     */
    public byte[] getseedactive()
    {
        return this.seedactive;
    }

    /**
     * this method sets the first node stored in the treehash instance itself
     *
     * @param hash
     */
    public void setfirstnode(byte[] hash)
    {
        if (!this.isinitialized)
        {
            this.initialize();
        }
        this.firstnode = hash;
        this.firstnodeheight = this.maxheight;
        this.isfinished = true;
    }

    /**
     * updates the nextseed of this treehash instance one step needed for the
     * schedulng of the seeds
     *
     * @param gmssrandom the prng used for the seeds
     */
    public void updatenextseed(gmssrandom gmssrandom)
    {
        gmssrandom.nextseed(seednext);
    }

    /**
     * returns the tailstack
     *
     * @return the tailstack
     */
    public vector gettailstack()
    {
        return this.tailstack;
    }

    /**
     * returns the status byte array used by the gmssprivatekeyasn.1 class
     *
     * @return the status bytes
     */
    public byte[][] getstatbyte()
    {

        byte[][] statbyte = new byte[3 + taillength][this.messdigesttree
            .getdigestsize()];
        statbyte[0] = firstnode;
        statbyte[1] = seedactive;
        statbyte[2] = seednext;
        for (int i = 0; i < taillength; i++)
        {
            statbyte[3 + i] = (byte[])tailstack.elementat(i);
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

        int[] statint = new int[6 + taillength];
        statint[0] = maxheight;
        statint[1] = taillength;
        statint[2] = firstnodeheight;
        if (this.isfinished)
        {
            statint[3] = 1;
        }
        else
        {
            statint[3] = 0;
        }
        if (this.isinitialized)
        {
            statint[4] = 1;
        }
        else
        {
            statint[4] = 0;
        }
        if (this.seedinitialized)
        {
            statint[5] = 1;
        }
        else
        {
            statint[5] = 0;
        }
        for (int i = 0; i < taillength; i++)
        {
            statint[6 + i] = ((integer)heightofnodes.elementat(i)).intvalue();
        }
        return statint;
    }

    /**
     * returns a string representation of the treehash instance
     */
    public string tostring()
    {
        string out = "treehash    : ";
        for (int i = 0; i < 6 + taillength; i++)
        {
            out = out + this.getstatint()[i] + " ";
        }
        for (int i = 0; i < 3 + taillength; i++)
        {
            if (this.getstatbyte()[i] != null)
            {
                out = out + new string(hex.encode((this.getstatbyte()[i]))) + " ";
            }
            else
            {
                out = out + "null ";
            }
        }
        out = out + "  " + this.messdigesttree.getdigestsize();
        return out;
    }

}