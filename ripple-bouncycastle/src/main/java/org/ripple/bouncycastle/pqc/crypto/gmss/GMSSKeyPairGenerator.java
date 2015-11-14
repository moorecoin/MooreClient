package org.ripple.bouncycastle.pqc.crypto.gmss;

import java.security.securerandom;
import java.util.vector;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypairgenerator;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.pqc.crypto.gmss.util.gmssrandom;
import org.ripple.bouncycastle.pqc.crypto.gmss.util.winternitzotsverify;
import org.ripple.bouncycastle.pqc.crypto.gmss.util.winternitzotsignature;


/**
 * this class implements key pair generation of the generalized merkle signature
 * scheme (gmss).
 *
 * @see gmsssigner
 */
public class gmsskeypairgenerator
    implements asymmetriccipherkeypairgenerator
{
    /**
     * the source of randomness for ots private key generation
     */
    private gmssrandom gmssrandom;

    /**
     * the hash function used for the construction of the authentication trees
     */
    private digest messdigesttree;

    /**
     * an array of the seeds for the prgn (for main tree, and all current
     * subtrees)
     */
    private byte[][] currentseeds;

    /**
     * an array of seeds for the prgn (for all subtrees after next)
     */
    private byte[][] nextnextseeds;

    /**
     * an array of the rootsignatures
     */
    private byte[][] currentrootsigs;

    /**
     * class of hash function to use
     */
    private gmssdigestprovider digestprovider;

    /**
     * the length of the seed for the prng
     */
    private int mdlength;

    /**
     * the number of layers
     */
    private int numlayer;


    /**
     * flag indicating if the class already has been initialized
     */
    private boolean initialized = false;

    /**
     * instance of gmssparameterset
     */
    private gmssparameters gmssps;

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

    private gmsskeygenerationparameters gmssparams;

    /**
     * the gmss oid.
     */
    public static final string oid = "1.3.6.1.4.1.8301.3.1.3.3";

    /**
     * the standard constructor tries to generate the gmss algorithm identifier
     * with the corresponding oid.
     * <p/>
     *
     * @param digestprovider     provider for digest implementations.
     */
    public gmsskeypairgenerator(gmssdigestprovider digestprovider)
    {
        this.digestprovider = digestprovider;
        messdigesttree = digestprovider.get();

        // set mdlength
        this.mdlength = messdigesttree.getdigestsize();
        // construct randomizer
        this.gmssrandom = new gmssrandom(messdigesttree);

    }

    /**
     * generates the gmss key pair. the public key is an instance of
     * jdkgmsspublickey, the private key is an instance of jdkgmssprivatekey.
     *
     * @return key pair containing a jdkgmsspublickey and a jdkgmssprivatekey
     */
    private asymmetriccipherkeypair genkeypair()
    {
        if (!initialized)
        {
            initializedefault();
        }

        // initialize authenticationpaths and treehash instances
        byte[][][] currentauthpaths = new byte[numlayer][][];
        byte[][][] nextauthpaths = new byte[numlayer - 1][][];
        treehash[][] currenttreehash = new treehash[numlayer][];
        treehash[][] nexttreehash = new treehash[numlayer - 1][];

        vector[] currentstack = new vector[numlayer];
        vector[] nextstack = new vector[numlayer - 1];

        vector[][] currentretain = new vector[numlayer][];
        vector[][] nextretain = new vector[numlayer - 1][];

        for (int i = 0; i < numlayer; i++)
        {
            currentauthpaths[i] = new byte[heightoftrees[i]][mdlength];
            currenttreehash[i] = new treehash[heightoftrees[i] - k[i]];

            if (i > 0)
            {
                nextauthpaths[i - 1] = new byte[heightoftrees[i]][mdlength];
                nexttreehash[i - 1] = new treehash[heightoftrees[i] - k[i]];
            }

            currentstack[i] = new vector();
            if (i > 0)
            {
                nextstack[i - 1] = new vector();
            }
        }

        // initialize roots
        byte[][] currentroots = new byte[numlayer][mdlength];
        byte[][] nextroots = new byte[numlayer - 1][mdlength];
        // initialize seeds
        byte[][] seeds = new byte[numlayer][mdlength];
        // initialize seeds[] by copying starting-seeds of first trees of each
        // layer
        for (int i = 0; i < numlayer; i++)
        {
            system.arraycopy(currentseeds[i], 0, seeds[i], 0, mdlength);
        }

        // initialize rootsigs
        currentrootsigs = new byte[numlayer - 1][mdlength];

        // -------------------------
        // -------------------------
        // --- calculation of current authpaths and current rootsigs (authpaths,
        // sig)------
        // from bottom up to the root
        for (int h = numlayer - 1; h >= 0; h--)
        {
            gmssrootcalc tree = new gmssrootcalc(this.heightoftrees[h], this.k[h], digestprovider);
            try
            {
                // on lowest layer no lower root is available, so just call
                // the method with null as first parameter
                if (h == numlayer - 1)
                {
                    tree = this.generatecurrentauthpathandroot(null, currentstack[h], seeds[h], h);
                }
                else
                // otherwise call the method with the former computed root
                // value
                {
                    tree = this.generatecurrentauthpathandroot(currentroots[h + 1], currentstack[h], seeds[h], h);
                }

            }
            catch (exception e1)
            {
                e1.printstacktrace();
            }

            // set initial values needed for the private key construction
            for (int i = 0; i < heightoftrees[h]; i++)
            {
                system.arraycopy(tree.getauthpath()[i], 0, currentauthpaths[h][i], 0, mdlength);
            }
            currentretain[h] = tree.getretain();
            currenttreehash[h] = tree.gettreehash();
            system.arraycopy(tree.getroot(), 0, currentroots[h], 0, mdlength);
        }

        // --- calculation of next authpaths and next roots (authpaths+, roots+)
        // ------
        for (int h = numlayer - 2; h >= 0; h--)
        {
            gmssrootcalc tree = this.generatenextauthpathandroot(nextstack[h], seeds[h + 1], h + 1);

            // set initial values needed for the private key construction
            for (int i = 0; i < heightoftrees[h + 1]; i++)
            {
                system.arraycopy(tree.getauthpath()[i], 0, nextauthpaths[h][i], 0, mdlength);
            }
            nextretain[h] = tree.getretain();
            nexttreehash[h] = tree.gettreehash();
            system.arraycopy(tree.getroot(), 0, nextroots[h], 0, mdlength);

            // create seed for the merkle tree after next (nextnextseeds)
            // seeds++
            system.arraycopy(seeds[h + 1], 0, this.nextnextseeds[h], 0, mdlength);
        }
        // ------------

        // generate jdkgmsspublickey
        gmsspublickeyparameters publickey = new gmsspublickeyparameters(currentroots[0], gmssps);

        // generate the jdkgmssprivatekey
        gmssprivatekeyparameters privatekey = new gmssprivatekeyparameters(currentseeds, nextnextseeds, currentauthpaths,
            nextauthpaths, currenttreehash, nexttreehash, currentstack, nextstack, currentretain, nextretain, nextroots, currentrootsigs, gmssps, digestprovider);

        // return the keypair
        return (new asymmetriccipherkeypair(publickey, privatekey));
    }

    /**
     * calculates the authpath for tree in layer h which starts with seed[h]
     * additionally computes the rootsignature of underlaying root
     *
     * @param currentstack stack used for the treehash instance created by this method
     * @param lowerroot    stores the root of the lower tree
     * @param seed        starting seeds
     * @param h            actual layer
     */
    private gmssrootcalc generatecurrentauthpathandroot(byte[] lowerroot, vector currentstack, byte[] seed, int h)
    {
        byte[] help = new byte[mdlength];

        byte[] otsseed = new byte[mdlength];
        otsseed = gmssrandom.nextseed(seed);

        winternitzotsignature ots;

        // data structure that constructs the whole tree and stores
        // the initial values for treehash, auth and retain
        gmssrootcalc treetoconstruct = new gmssrootcalc(this.heightoftrees[h], this.k[h], digestprovider);

        treetoconstruct.initialize(currentstack);

        // generate the first leaf
        if (h == numlayer - 1)
        {
            ots = new winternitzotsignature(otsseed, digestprovider.get(), otsindex[h]);
            help = ots.getpublickey();
        }
        else
        {
            // for all layers except the lowest, generate the signature of the
            // underlying root
            // and reuse this signature to compute the first leaf of acual layer
            // more efficiently (by verifiing the signature)
            ots = new winternitzotsignature(otsseed, digestprovider.get(), otsindex[h]);
            currentrootsigs[h] = ots.getsignature(lowerroot);
            winternitzotsverify otsver = new winternitzotsverify(digestprovider.get(), otsindex[h]);
            help = otsver.verify(lowerroot, currentrootsigs[h]);
        }
        // update the tree with the first leaf
        treetoconstruct.update(help);

        int seedfortreehashindex = 3;
        int count = 0;

        // update the tree 2^(h) - 1 times, from the second to the last leaf
        for (int i = 1; i < (1 << this.heightoftrees[h]); i++)
        {
            // initialize the seeds for the leaf generation with index 3 * 2^h
            if (i == seedfortreehashindex && count < this.heightoftrees[h] - this.k[h])
            {
                treetoconstruct.initializetreehashseed(seed, count);
                seedfortreehashindex *= 2;
                count++;
            }

            otsseed = gmssrandom.nextseed(seed);
            ots = new winternitzotsignature(otsseed, digestprovider.get(), otsindex[h]);
            treetoconstruct.update(ots.getpublickey());
        }

        if (treetoconstruct.wasfinished())
        {
            return treetoconstruct;
        }
        system.err.println("baum noch nicht fertig konstruiert!!!");
        return null;
    }

    /**
     * calculates the authpath and root for tree in layer h which starts with
     * seed[h]
     *
     * @param nextstack stack used for the treehash instance created by this method
     * @param seed      starting seeds
     * @param h         actual layer
     */
    private gmssrootcalc generatenextauthpathandroot(vector nextstack, byte[] seed, int h)
    {
        byte[] otsseed = new byte[numlayer];
        winternitzotsignature ots;

        // data structure that constructs the whole tree and stores
        // the initial values for treehash, auth and retain
        gmssrootcalc treetoconstruct = new gmssrootcalc(this.heightoftrees[h], this.k[h], this.digestprovider);
        treetoconstruct.initialize(nextstack);

        int seedfortreehashindex = 3;
        int count = 0;

        // update the tree 2^(h) times, from the first to the last leaf
        for (int i = 0; i < (1 << this.heightoftrees[h]); i++)
        {
            // initialize the seeds for the leaf generation with index 3 * 2^h
            if (i == seedfortreehashindex && count < this.heightoftrees[h] - this.k[h])
            {
                treetoconstruct.initializetreehashseed(seed, count);
                seedfortreehashindex *= 2;
                count++;
            }

            otsseed = gmssrandom.nextseed(seed);
            ots = new winternitzotsignature(otsseed, digestprovider.get(), otsindex[h]);
            treetoconstruct.update(ots.getpublickey());
        }

        if (treetoconstruct.wasfinished())
        {
            return treetoconstruct;
        }
        system.err.println("n锟絚hster baum noch nicht fertig konstruiert!!!");
        return null;
    }

    /**
     * this method initializes the gmss keypairgenerator using an integer value
     * <code>keysize</code> as input. it provides a simple use of the gmss for
     * testing demands.
     * <p/>
     * a given <code>keysize</code> of less than 10 creates an amount 2^10
     * signatures. a keysize between 10 and 20 creates 2^20 signatures. given an
     * integer greater than 20 the key pair generator creates 2^40 signatures.
     *
     * @param keysize      assigns the parameters used for the gmss signatures. there are
     *                     3 choices:<br/>
     *                     1. keysize <= 10: creates 2^10 signatures using the
     *                     parameterset<br/>
     *                     p = (2, (5, 5), (3, 3), (3, 3))<br/>
     *                     2. keysize > 10 and <= 20: creates 2^20 signatures using the
     *                     parameterset<br/>
     *                     p = (2, (10, 10), (5, 4), (2, 2))<br/>
     *                     3. keysize > 20: creates 2^40 signatures using the
     *                     parameterset<br/>
     *                     p = (2, (10, 10, 10, 10), (9, 9, 9, 3), (2, 2, 2, 2))
     * @param securerandom not used by gmss, the sha1prng of the sun provider is always
     *                     used
     */
    public void initialize(int keysize, securerandom securerandom)
    {

        keygenerationparameters kgp;
        if (keysize <= 10)
        { // create 2^10 keys
            int[] defh = {10};
            int[] defw = {3};
            int[] defk = {2};
            // xxx sec random neede?
            kgp = new gmsskeygenerationparameters(securerandom, new gmssparameters(defh.length, defh, defw, defk));
        }
        else if (keysize <= 20)
        { // create 2^20 keys
            int[] defh = {10, 10};
            int[] defw = {5, 4};
            int[] defk = {2, 2};
            kgp = new gmsskeygenerationparameters(securerandom, new gmssparameters(defh.length, defh, defw, defk));
        }
        else
        { // create 2^40 keys, keygen lasts around 80 seconds
            int[] defh = {10, 10, 10, 10};
            int[] defw = {9, 9, 9, 3};
            int[] defk = {2, 2, 2, 2};
            kgp = new gmsskeygenerationparameters(securerandom, new gmssparameters(defh.length, defh, defw, defk));
        }

        // call the initializer with the chosen parameters
        this.initialize(kgp);

    }


    /**
     * initalizes the key pair generator using a parameter set as input
     */
    public void initialize(keygenerationparameters param)
    {

        this.gmssparams = (gmsskeygenerationparameters)param;

        // generate gmssparameterset
        this.gmssps = new gmssparameters(gmssparams.getparameters().getnumoflayers(), gmssparams.getparameters().getheightoftrees(),
            gmssparams.getparameters().getwinternitzparameter(), gmssparams.getparameters().getk());

        this.numlayer = gmssps.getnumoflayers();
        this.heightoftrees = gmssps.getheightoftrees();
        this.otsindex = gmssps.getwinternitzparameter();
        this.k = gmssps.getk();

        // seeds
        this.currentseeds = new byte[numlayer][mdlength];
        this.nextnextseeds = new byte[numlayer - 1][mdlength];

        // construct securerandom for initial seed generation
        securerandom secran = new securerandom();

        // generation of initial seeds
        for (int i = 0; i < numlayer; i++)
        {
            secran.nextbytes(currentseeds[i]);
            gmssrandom.nextseed(currentseeds[i]);
        }

        this.initialized = true;
    }

    /**
     * this method is called by generatekeypair() in case that no other
     * initialization method has been called by the user
     */
    private void initializedefault()
    {
        int[] defh = {10, 10, 10, 10};
        int[] defw = {3, 3, 3, 3};
        int[] defk = {2, 2, 2, 2};

        keygenerationparameters kgp = new gmsskeygenerationparameters(new securerandom(), new gmssparameters(defh.length, defh, defw, defk));
        this.initialize(kgp);

    }

    public void init(keygenerationparameters param)
    {
        this.initialize(param);

    }

    public asymmetriccipherkeypair generatekeypair()
    {
        return genkeypair();
    }
}
