package org.ripple.bouncycastle.pqc.crypto.gmss;

import java.util.vector;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.pqc.crypto.gmss.util.gmssrandom;
import org.ripple.bouncycastle.pqc.crypto.gmss.util.winternitzotsignature;
import org.ripple.bouncycastle.util.arrays;


/**
 * this class provides a specification for a gmss private key.
 */
public class gmssprivatekeyparameters
    extends gmsskeyparameters
{
    private int[] index;

    private byte[][] currentseeds;
    private byte[][] nextnextseeds;

    private byte[][][] currentauthpaths;
    private byte[][][] nextauthpaths;

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

    private gmssdigestprovider digestprovider;

    private boolean used = false;

    /**
     * an array of the heights of the authentication trees of each layer
     */
    private int[] heightoftrees;

    /**
     * an array of the winternitz parameter 'w' of each layer
     */
    private int[] otsindex;

    /**
     * the parameter k needed for the authentication path computation
     */
    private int[] k;

    /**
     * the number of layers
     */
    private int numlayer;

    /**
     * the hash function used to construct the authentication trees
     */
    private digest messdigesttrees;

    /**
     * the message digest length
     */
    private int mdlength;

    /**
     * the prng used for private key generation
     */
    private gmssrandom gmssrandom;


    /**
     * the number of leafs of one tree of each layer
     */
    private int[] numleafs;


    /**
     * generates a new gmss private key
     *
     * @param currentseed      seed for the generation of private ots keys for the
     *                         current subtrees
     * @param nextnextseed     seed for the generation of private ots keys for the next
     *                         subtrees
     * @param currentauthpath  array of current authentication paths
     * @param nextauthpath     array of next authentication paths
     * @param currenttreehash  array of current treehash instances
     * @param nexttreehash     array of next treehash instances
     * @param currentstack     array of current shared stacks
     * @param nextstack        array of next shared stacks
     * @param currentretain    array of current retain stacks
     * @param nextretain       array of next retain stacks
     * @param nextroot         the roots of the next subtree
     * @param currentrootsig   array of signatures of the roots of the current subtrees
     * @param gmssparameterset the gmss parameterset
     * @see org.ripple.bouncycastle.pqc.crypto.gmss.gmsskeypairgenerator
     */

    public gmssprivatekeyparameters(byte[][] currentseed, byte[][] nextnextseed,
                                    byte[][][] currentauthpath, byte[][][] nextauthpath,
                                    treehash[][] currenttreehash, treehash[][] nexttreehash,
                                    vector[] currentstack, vector[] nextstack,
                                    vector[][] currentretain, vector[][] nextretain, byte[][] nextroot,
                                    byte[][] currentrootsig, gmssparameters gmssparameterset,
                                    gmssdigestprovider digestprovider)
    {
        this(null, currentseed, nextnextseed, currentauthpath, nextauthpath,
            null, currenttreehash, nexttreehash, currentstack, nextstack,
            currentretain, nextretain, null, null, null, null, nextroot,
            null, currentrootsig, null, gmssparameterset, digestprovider);
    }

    /**
     * /**
     *
     * @param index             tree indices
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
    public gmssprivatekeyparameters(int[] index, byte[][] currentseeds,
                                    byte[][] nextnextseeds, byte[][][] currentauthpaths,
                                    byte[][][] nextauthpaths, byte[][][] keep,
                                    treehash[][] currenttreehash, treehash[][] nexttreehash,
                                    vector[] currentstack, vector[] nextstack,
                                    vector[][] currentretain, vector[][] nextretain,
                                    gmssleaf[] nextnextleaf, gmssleaf[] upperleaf,
                                    gmssleaf[] uppertreehashleaf, int[] mintreehash, byte[][] nextroot,
                                    gmssrootcalc[] nextnextroot, byte[][] currentrootsig,
                                    gmssrootsig[] nextrootsig, gmssparameters gmssparameterset,
                                    gmssdigestprovider digestprovider)
    {

        super(true, gmssparameterset);

        // construct message digest

        this.messdigesttrees = digestprovider.get();
        this.mdlength = messdigesttrees.getdigestsize();


        // parameter
        this.gmssps = gmssparameterset;
        this.otsindex = gmssparameterset.getwinternitzparameter();
        this.k = gmssparameterset.getk();
        this.heightoftrees = gmssparameterset.getheightoftrees();
        // initialize numlayer
        this.numlayer = gmssps.getnumoflayers();

        // initialize index if null
        if (index == null)
        {
            this.index = new int[numlayer];
            for (int i = 0; i < numlayer; i++)
            {
                this.index[i] = 0;
            }
        }
        else
        {
            this.index = index;
        }

        this.currentseeds = currentseeds;
        this.nextnextseeds = nextnextseeds;

        this.currentauthpaths = currentauthpaths;
        this.nextauthpaths = nextauthpaths;

        // initialize keep if null
        if (keep == null)
        {
            this.keep = new byte[numlayer][][];
            for (int i = 0; i < numlayer; i++)
            {
                this.keep[i] = new byte[(int)math.floor(heightoftrees[i] / 2)][mdlength];
            }
        }
        else
        {
            this.keep = keep;
        }

        // initialize stack if null
        if (currentstack == null)
        {
            this.currentstack = new vector[numlayer];
            for (int i = 0; i < numlayer; i++)
            {
                this.currentstack[i] = new vector();
            }
        }
        else
        {
            this.currentstack = currentstack;
        }

        // initialize nextstack if null
        if (nextstack == null)
        {
            this.nextstack = new vector[numlayer - 1];
            for (int i = 0; i < numlayer - 1; i++)
            {
                this.nextstack[i] = new vector();
            }
        }
        else
        {
            this.nextstack = nextstack;
        }

        this.currenttreehash = currenttreehash;
        this.nexttreehash = nexttreehash;

        this.currentretain = currentretain;
        this.nextretain = nextretain;

        this.nextroot = nextroot;

        this.digestprovider = digestprovider;

        if (nextnextroot == null)
        {
            this.nextnextroot = new gmssrootcalc[numlayer - 1];
            for (int i = 0; i < numlayer - 1; i++)
            {
                this.nextnextroot[i] = new gmssrootcalc(
                    this.heightoftrees[i + 1], this.k[i + 1], this.digestprovider);
            }
        }
        else
        {
            this.nextnextroot = nextnextroot;
        }
        this.currentrootsig = currentrootsig;

        // calculate numleafs
        numleafs = new int[numlayer];
        for (int i = 0; i < numlayer; i++)
        {
            numleafs[i] = 1 << heightoftrees[i];
        }
        // construct prng
        this.gmssrandom = new gmssrandom(messdigesttrees);

        if (numlayer > 1)
        {
            // construct the nextnextleaf (leafs++) array for upcoming leafs in
            // tree after next (tree++)
            if (nextnextleaf == null)
            {
                this.nextnextleaf = new gmssleaf[numlayer - 2];
                for (int i = 0; i < numlayer - 2; i++)
                {
                    this.nextnextleaf[i] = new gmssleaf(digestprovider.get(), otsindex[i + 1], numleafs[i + 2], this.nextnextseeds[i]);
                }
            }
            else
            {
                this.nextnextleaf = nextnextleaf;
            }
        }
        else
        {
            this.nextnextleaf = new gmssleaf[0];
        }

        // construct the upperleaf array for upcoming leafs in tree over the
        // actual
        if (upperleaf == null)
        {
            this.upperleaf = new gmssleaf[numlayer - 1];
            for (int i = 0; i < numlayer - 1; i++)
            {
                this.upperleaf[i] = new gmssleaf(digestprovider.get(), otsindex[i],
                    numleafs[i + 1], this.currentseeds[i]);
            }
        }
        else
        {
            this.upperleaf = upperleaf;
        }

        // construct the leafs for upcoming leafs in treehashs in tree over the
        // actual
        if (uppertreehashleaf == null)
        {
            this.uppertreehashleaf = new gmssleaf[numlayer - 1];
            for (int i = 0; i < numlayer - 1; i++)
            {
                this.uppertreehashleaf[i] = new gmssleaf(digestprovider.get(), otsindex[i], numleafs[i + 1]);
            }
        }
        else
        {
            this.uppertreehashleaf = uppertreehashleaf;
        }

        if (mintreehash == null)
        {
            this.mintreehash = new int[numlayer - 1];
            for (int i = 0; i < numlayer - 1; i++)
            {
                this.mintreehash[i] = -1;
            }
        }
        else
        {
            this.mintreehash = mintreehash;
        }

        // construct the nextrootsig (rootsig++)
        byte[] dummy = new byte[mdlength];
        byte[] otsseed = new byte[mdlength];
        if (nextrootsig == null)
        {
            this.nextrootsig = new gmssrootsig[numlayer - 1];
            for (int i = 0; i < numlayer - 1; i++)
            {
                system.arraycopy(currentseeds[i], 0, dummy, 0, mdlength);
                gmssrandom.nextseed(dummy);
                otsseed = gmssrandom.nextseed(dummy);
                this.nextrootsig[i] = new gmssrootsig(digestprovider.get(), otsindex[i],
                    heightoftrees[i + 1]);
                this.nextrootsig[i].initsign(otsseed, nextroot[i]);
            }
        }
        else
        {
            this.nextrootsig = nextrootsig;
        }
    }

    // we assume this only gets called from nextkey so used is never copied.
    private gmssprivatekeyparameters(gmssprivatekeyparameters original)
    {
        super(true, original.getparameters());

        this.index = arrays.clone(original.index);
        this.currentseeds = arrays.clone(original.currentseeds);
        this.nextnextseeds = arrays.clone(original.nextnextseeds);
        this.currentauthpaths = arrays.clone(original.currentauthpaths);
        this.nextauthpaths = arrays.clone(original.nextauthpaths);
        this.currenttreehash = original.currenttreehash;
        this.nexttreehash = original.nexttreehash;
        this.currentstack = original.currentstack;
        this.nextstack = original.nextstack;
        this.currentretain = original.currentretain;
        this.nextretain = original.nextretain;
        this.keep = arrays.clone(original.keep);
        this.nextnextleaf = original.nextnextleaf;
        this.upperleaf = original.upperleaf;
        this.uppertreehashleaf = original.uppertreehashleaf;
        this.mintreehash = original.mintreehash;
        this.gmssps = original.gmssps;
        this.nextroot = arrays.clone(original.nextroot);
        this.nextnextroot = original.nextnextroot;
        this.currentrootsig = original.currentrootsig;
        this.nextrootsig = original.nextrootsig;
        this.digestprovider = original.digestprovider;
        this.heightoftrees = original.heightoftrees;
        this.otsindex = original.otsindex;
        this.k = original.k;
        this.numlayer = original.numlayer;
        this.messdigesttrees = original.messdigesttrees;
        this.mdlength = original.mdlength;
        this.gmssrandom = original.gmssrandom;
        this.numleafs = original.numleafs;
    }

    public boolean isused()
    {
        return this.used;
    }

    public void markused()
    {
        this.used = true;
    }

    public gmssprivatekeyparameters nextkey()
    {
        gmssprivatekeyparameters nkey = new gmssprivatekeyparameters(this);

        nkey.nextkey(gmssps.getnumoflayers() - 1);

        return nkey;
    }

    /**
     * this method updates the gmss private key for the next signature
     *
     * @param layer the layer where the next key is processed
     */
    private void nextkey(int layer)
    {
        // only for lowest layer ( other layers indices are raised in nexttree()
        // method )
        if (layer == numlayer - 1)
        {
            index[layer]++;
        } // else system.out.println(" --- nextkey on layer " + layer + "
        // index is now : " + index[layer]);

        // if tree of this layer is depleted
        if (index[layer] == numleafs[layer])
        {
            if (numlayer != 1)
            {
                nexttree(layer);
                index[layer] = 0;
            }
        }
        else
        {
            updatekey(layer);
        }
    }

    /**
     * switch to next subtree if the current one is depleted
     *
     * @param layer the layer where the next tree is processed
     */
    private void nexttree(int layer)
    {
        // system.out.println("nexttree method called on layer " + layer);
        // dont create next tree for the top layer
        if (layer > 0)
        {
            // raise index for upper layer
            index[layer - 1]++;

            // test if it is already the last tree
            boolean lasttree = true;
            int z = layer;
            do
            {
                z--;
                if (index[z] < numleafs[z])
                {
                    lasttree = false;
                }
            }
            while (lasttree && (z > 0));

            // only construct next subtree if last one is not already in use
            if (!lasttree)
            {
                gmssrandom.nextseed(currentseeds[layer]);

                // last step of distributed signature calculation
                nextrootsig[layer - 1].updatesign();

                // last step of distributed leaf calculation for nextnextleaf
                if (layer > 1)
                {
                    nextnextleaf[layer - 1 - 1] = nextnextleaf[layer - 1 - 1].nextleaf();
                }

                // last step of distributed leaf calculation for upper leaf
                upperleaf[layer - 1] = upperleaf[layer - 1].nextleaf();

                // last step of distributed leaf calculation for all treehashs

                if (mintreehash[layer - 1] >= 0)
                {
                    uppertreehashleaf[layer - 1] = uppertreehashleaf[layer - 1].nextleaf();
                    byte[] leaf = this.uppertreehashleaf[layer - 1].getleaf();
                    // if update is required use the precomputed leaf to update
                    // treehash
                    try
                    {
                        currenttreehash[layer - 1][mintreehash[layer - 1]]
                            .update(this.gmssrandom, leaf);
                        // system.out.println("uuupdated th " +
                        // mintreehash[layer - 1]);
                        if (currenttreehash[layer - 1][mintreehash[layer - 1]]
                            .wasfinished())
                        {
                            // system.out.println("fffinished th " +
                            // mintreehash[layer - 1]);
                        }
                    }
                    catch (exception e)
                    {
                        system.out.println(e);
                    }
                }

                // last step of nextnextauthroot calculation
                this.updatenextnextauthroot(layer);

                // ******************************************************** /

                // now: advance to next tree on layer 'layer'

                // nextrootsig --> currentrootsigs
                this.currentrootsig[layer - 1] = nextrootsig[layer - 1]
                    .getsig();

                // -----------------------

                // nexttreehash --> currenttreehash
                // nextnexttreehash --> nexttreehash
                for (int i = 0; i < heightoftrees[layer] - k[layer]; i++)
                {
                    this.currenttreehash[layer][i] = this.nexttreehash[layer - 1][i];
                    this.nexttreehash[layer - 1][i] = this.nextnextroot[layer - 1]
                        .gettreehash()[i];
                }

                // nextauthpath --> currentauthpath
                // nextnextauthpath --> nextauthpath
                for (int i = 0; i < heightoftrees[layer]; i++)
                {
                    system.arraycopy(nextauthpaths[layer - 1][i], 0,
                        currentauthpaths[layer][i], 0, mdlength);
                    system.arraycopy(nextnextroot[layer - 1].getauthpath()[i],
                        0, nextauthpaths[layer - 1][i], 0, mdlength);
                }

                // nextretain --> currentretain
                // nextnextretain --> nextretain
                for (int i = 0; i < k[layer] - 1; i++)
                {
                    this.currentretain[layer][i] = this.nextretain[layer - 1][i];
                    this.nextretain[layer - 1][i] = this.nextnextroot[layer - 1]
                        .getretain()[i];
                }

                // nextstack --> currentstack
                this.currentstack[layer] = this.nextstack[layer - 1];
                // nextnextstack --> nextstack
                this.nextstack[layer - 1] = this.nextnextroot[layer - 1]
                    .getstack();

                // nextnextroot --> nextroot
                this.nextroot[layer - 1] = this.nextnextroot[layer - 1]
                    .getroot();
                // -----------------------

                // -----------------
                byte[] otsseed = new byte[mdlength];
                byte[] dummy = new byte[mdlength];
                // gmssrandom.setseed(currentseeds[layer]);
                system
                    .arraycopy(currentseeds[layer - 1], 0, dummy, 0,
                        mdlength);
                otsseed = gmssrandom.nextseed(dummy); // only need otsseed
                otsseed = gmssrandom.nextseed(dummy);
                otsseed = gmssrandom.nextseed(dummy);
                // nextwinsig[layer-1]=new
                // gmsswinsig(otsseed,algnames,otsindex[layer-1],heightoftrees[layer],nextroot[layer-1]);
                nextrootsig[layer - 1].initsign(otsseed, nextroot[layer - 1]);

                // nextkey for upper layer
                nextkey(layer - 1);
            }
        }
    }

    /**
     * this method computes the authpath (auth) for the current tree,
     * additionally the root signature for the next tree (sig+), the authpath
     * (auth++) and root (root++) for the tree after next in layer
     * <code>layer</code>, and the leaf++^1 for the next next tree in the
     * layer above are updated this method is used by nextkey()
     *
     * @param layer
     */
    private void updatekey(int layer)
    {
        // ----------current tree processing of actual layer---------
        // compute upcoming authpath for current tree (auth)
        computeauthpaths(layer);

        // -----------distributed calculations part------------
        // not for highest tree layer
        if (layer > 0)
        {

            // compute (partial) next leaf on tree++ (not on layer 1 and 0)
            if (layer > 1)
            {
                nextnextleaf[layer - 1 - 1] = nextnextleaf[layer - 1 - 1].nextleaf();
            }

            // compute (partial) next leaf on tree above (not on layer 0)
            upperleaf[layer - 1] = upperleaf[layer - 1].nextleaf();

            // compute (partial) next leaf for all treehashs on tree above (not
            // on layer 0)

            int t = (int)math
                .floor((double)(this.getnumleafs(layer) * 2)
                    / (double)(this.heightoftrees[layer - 1] - this.k[layer - 1]));

            if (index[layer] % t == 1)
            {
                // system.out.println(" layer: " + layer + " index: " +
                // index[layer] + " t : " + t);

                // take precomputed node for treehash update
                // ------------------------------------------------
                if (index[layer] > 1 && mintreehash[layer - 1] >= 0)
                {
                    byte[] leaf = this.uppertreehashleaf[layer - 1].getleaf();
                    // if update is required use the precomputed leaf to update
                    // treehash
                    try
                    {
                        currenttreehash[layer - 1][mintreehash[layer - 1]]
                            .update(this.gmssrandom, leaf);
                        // system.out.println("updated th " + mintreehash[layer
                        // - 1]);
                        if (currenttreehash[layer - 1][mintreehash[layer - 1]]
                            .wasfinished())
                        {
                            // system.out.println("finished th " +
                            // mintreehash[layer - 1]);
                        }
                    }
                    catch (exception e)
                    {
                        system.out.println(e);
                    }
                    // ------------------------------------------------
                }

                // initialize next leaf precomputation
                // ------------------------------------------------

                // get lowest index of treehashs
                this.mintreehash[layer - 1] = getmintreehashindex(layer - 1);

                if (this.mintreehash[layer - 1] >= 0)
                {
                    // initialize leaf
                    byte[] seed = this.currenttreehash[layer - 1][this.mintreehash[layer - 1]]
                        .getseedactive();
                    this.uppertreehashleaf[layer - 1] = new gmssleaf(
                        this.digestprovider.get(), this.otsindex[layer - 1], t, seed);
                    this.uppertreehashleaf[layer - 1] = this.uppertreehashleaf[layer - 1].nextleaf();
                    // system.out.println("restarted treehashleaf (" + (layer -
                    // 1) + "," + this.mintreehash[layer - 1] + ")");
                }
                // ------------------------------------------------

            }
            else
            {
                // update the upper leaf for the treehash one step
                if (this.mintreehash[layer - 1] >= 0)
                {
                    this.uppertreehashleaf[layer - 1] = this.uppertreehashleaf[layer - 1].nextleaf();
                    // if (mintreehash[layer - 1] > 3)
                    // system.out.print("#");
                }
            }

            // compute (partial) the signature of root+ (rootsig+) (not on top
            // layer)
            nextrootsig[layer - 1].updatesign();

            // compute (partial) authpath++ & root++ (not on top layer)
            if (index[layer] == 1)
            {
                // init root and authpath calculation for tree after next
                // (auth++, root++)
                this.nextnextroot[layer - 1].initialize(new vector());
            }

            // update root and authpath calculation for tree after next (auth++,
            // root++)
            this.updatenextnextauthroot(layer);
        }
        // ----------- end distributed calculations part-----------------
    }

    /**
     * this method returns the index of the next treehash instance that should
     * receive an update
     *
     * @param layer the layer of the gmss tree
     * @return index of the treehash instance that should get the update
     */
    private int getmintreehashindex(int layer)
    {
        int mintreehash = -1;
        for (int h = 0; h < heightoftrees[layer] - k[layer]; h++)
        {
            if (currenttreehash[layer][h].wasinitialized()
                && !currenttreehash[layer][h].wasfinished())
            {
                if (mintreehash == -1)
                {
                    mintreehash = h;
                }
                else if (currenttreehash[layer][h].getlowestnodeheight() < currenttreehash[layer][mintreehash]
                    .getlowestnodeheight())
                {
                    mintreehash = h;
                }
            }
        }
        return mintreehash;
    }

    /**
     * computes the upcoming currentauthpath of layer <code>layer</code> using
     * the revisited authentication path computation of dahmen/schneider 2008
     *
     * @param layer the actual layer
     */
    private void computeauthpaths(int layer)
    {

        int phi = index[layer];
        int h = heightoftrees[layer];
        int k = this.k[layer];

        // update all nextseeds for seed scheduling
        for (int i = 0; i < h - k; i++)
        {
            currenttreehash[layer][i].updatenextseed(gmssrandom);
        }

        // step 1 of algorithm
        int tau = heightofphi(phi);

        byte[] otsseed = new byte[mdlength];
        otsseed = gmssrandom.nextseed(currentseeds[layer]);

        // step 2 of algorithm
        // if phi's parent on height tau + 1 if left node, store auth_tau
        // in keep_tau.
        // todo check it, formerly was
        // int l = phi / (int) math.floor(math.pow(2, tau + 1));
        // l %= 2;
        int l = (phi >>> (tau + 1)) & 1;

        byte[] tempkeep = new byte[mdlength];
        // store the keep node not in keep[layer][tau/2] because it might be in
        // use
        // wait until the space is freed in step 4a
        if (tau < h - 1 && l == 0)
        {
            system.arraycopy(currentauthpaths[layer][tau], 0, tempkeep, 0,
                mdlength);
        }

        byte[] help = new byte[mdlength];
        // step 3 of algorithm
        // if phi is left child, compute and store leaf for next currentauthpath
        // path,
        // (obtained by veriying current signature)
        if (tau == 0)
        {
            // leafcalc !!!
            if (layer == numlayer - 1)
            { // lowest layer computes the
                // necessary leaf completely at this
                // time
                winternitzotsignature ots = new winternitzotsignature(otsseed,
                    digestprovider.get(), otsindex[layer]);
                help = ots.getpublickey();
            }
            else
            { // other layers use the precomputed leafs in
                // nextnextleaf
                byte[] dummy = new byte[mdlength];
                system.arraycopy(currentseeds[layer], 0, dummy, 0, mdlength);
                gmssrandom.nextseed(dummy);
                help = upperleaf[layer].getleaf();
                this.upperleaf[layer].initleafcalc(dummy);

                // winternitzotsverify otsver = new
                // winternitzotsverify(algnames, otsindex[layer]);
                // byte[] help2 = otsver.verify(currentroot[layer],
                // currentrootsig[layer]);
                // system.out.println(" --- " + layer + " " +
                // byteutils.tohexstring(help) + " " +
                // byteutils.tohexstring(help2));
            }
            system.arraycopy(help, 0, currentauthpaths[layer][0], 0, mdlength);
        }
        else
        {
            // step 4a of algorithm
            // get new left currentauthpath node on height tau
            byte[] tobehashed = new byte[mdlength << 1];
            system.arraycopy(currentauthpaths[layer][tau - 1], 0, tobehashed,
                0, mdlength);
            // free the shared keep[layer][tau/2]
            system.arraycopy(keep[layer][(int)math.floor((tau - 1) / 2)], 0,
                tobehashed, mdlength, mdlength);
            messdigesttrees.update(tobehashed, 0, tobehashed.length);
            currentauthpaths[layer][tau] = new byte[messdigesttrees.getdigestsize()];
            messdigesttrees.dofinal(currentauthpaths[layer][tau], 0);

            // step 4b and 4c of algorithm
            // copy right nodes to currentauthpath on height 0..tau-1
            for (int i = 0; i < tau; i++)
            {

                // step 4b of algorithm
                // 1st: copy from treehashs
                if (i < h - k)
                {
                    if (currenttreehash[layer][i].wasfinished())
                    {
                        system.arraycopy(currenttreehash[layer][i]
                            .getfirstnode(), 0, currentauthpaths[layer][i],
                            0, mdlength);
                        currenttreehash[layer][i].destroy();
                    }
                    else
                    {
                        system.err
                            .println("treehash ("
                                + layer
                                + ","
                                + i
                                + ") not finished when needed in authpathcomputation");
                    }
                }

                // 2nd: copy precomputed values from retain
                if (i < h - 1 && i >= h - k)
                {
                    if (currentretain[layer][i - (h - k)].size() > 0)
                    {
                        // pop element from retain
                        system.arraycopy(currentretain[layer][i - (h - k)]
                            .lastelement(), 0, currentauthpaths[layer][i],
                            0, mdlength);
                        currentretain[layer][i - (h - k)]
                            .removeelementat(currentretain[layer][i
                                - (h - k)].size() - 1);
                    }
                }

                // step 4c of algorithm
                // initialize new stack at heights 0..tau-1
                if (i < h - k)
                {
                    // create stacks anew
                    int startpoint = phi + 3 * (1 << i);
                    if (startpoint < numleafs[layer])
                    {
                        // if (layer < 2) {
                        // system.out.println("initialized th " + i + " on layer
                        // " + layer);
                        // }
                        currenttreehash[layer][i].initialize();
                    }
                }
            }
        }

        // now keep space is free to use
        if (tau < h - 1 && l == 0)
        {
            system.arraycopy(tempkeep, 0,
                keep[layer][(int)math.floor(tau / 2)], 0, mdlength);
        }

        // only update empty stack at height h if all other stacks have
        // tailnodes with height >h
        // finds active stack with lowest node height, choses lower index in
        // case of tie

        // on the lowest layer leafs must be computed at once, no precomputation
        // is possible. so all treehash updates are done at once here
        if (layer == numlayer - 1)
        {
            for (int tmp = 1; tmp <= (h - k) / 2; tmp++)
            {
                // index of the treehash instance that receives the next update
                int mintreehash = getmintreehashindex(layer);

                // if active treehash is found update with a leaf
                if (mintreehash >= 0)
                {
                    try
                    {
                        byte[] seed = new byte[mdlength];
                        system.arraycopy(
                            this.currenttreehash[layer][mintreehash]
                                .getseedactive(), 0, seed, 0, mdlength);
                        byte[] seed2 = gmssrandom.nextseed(seed);
                        winternitzotsignature ots = new winternitzotsignature(
                            seed2, this.digestprovider.get(), this.otsindex[layer]);
                        byte[] leaf = ots.getpublickey();
                        currenttreehash[layer][mintreehash].update(
                            this.gmssrandom, leaf);
                    }
                    catch (exception e)
                    {
                        system.out.println(e);
                    }
                }
            }
        }
        else
        { // on higher layers the updates are done later
            this.mintreehash[layer] = getmintreehashindex(layer);
        }
    }

    /**
     * returns the largest h such that 2^h | phi
     *
     * @param phi the leaf index
     * @return the largest <code>h</code> with <code>2^h | phi</code> if
     *         <code>phi!=0</code> else return <code>-1</code>
     */
    private int heightofphi(int phi)
    {
        if (phi == 0)
        {
            return -1;
        }
        int tau = 0;
        int modul = 1;
        while (phi % modul == 0)
        {
            modul *= 2;
            tau += 1;
        }
        return tau - 1;
    }

    /**
     * updates the authentication path and root calculation for the tree after
     * next (auth++, root++) in layer <code>layer</code>
     *
     * @param layer
     */
    private void updatenextnextauthroot(int layer)
    {

        byte[] otsseed = new byte[mdlength];
        otsseed = gmssrandom.nextseed(nextnextseeds[layer - 1]);

        // get the necessary leaf
        if (layer == numlayer - 1)
        { // lowest layer computes the necessary
            // leaf completely at this time
            winternitzotsignature ots = new winternitzotsignature(otsseed,
                digestprovider.get(), otsindex[layer]);
            this.nextnextroot[layer - 1].update(nextnextseeds[layer - 1], ots
                .getpublickey());
        }
        else
        { // other layers use the precomputed leafs in nextnextleaf
            this.nextnextroot[layer - 1].update(nextnextseeds[layer - 1], nextnextleaf[layer - 1].getleaf());
            this.nextnextleaf[layer - 1].initleafcalc(nextnextseeds[layer - 1]);
        }
    }

    public int[] getindex()
    {
        return index;
    }

    /**
     * @return the current index of layer i
     */
    public int getindex(int i)
    {
        return index[i];
    }

    public byte[][] getcurrentseeds()
    {
        return arrays.clone(currentseeds);
    }

    public byte[][][] getcurrentauthpaths()
    {
        return arrays.clone(currentauthpaths);
    }

    /**
     * @return the one-time signature of the root of the current subtree
     */
    public byte[] getsubtreerootsig(int i)
    {
        return currentrootsig[i];
    }


    public gmssdigestprovider getname()
    {
        return digestprovider;
    }

    /**
     * @return the number of leafs of each tree of layer i
     */
    public int getnumleafs(int i)
    {
        return numleafs[i];
    }
}
