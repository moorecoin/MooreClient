package org.ripple.bouncycastle.pqc.crypto.gmss;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.pqc.crypto.messagesigner;
import org.ripple.bouncycastle.pqc.crypto.gmss.util.gmssrandom;
import org.ripple.bouncycastle.pqc.crypto.gmss.util.gmssutil;
import org.ripple.bouncycastle.pqc.crypto.gmss.util.winternitzotsverify;
import org.ripple.bouncycastle.pqc.crypto.gmss.util.winternitzotsignature;
import org.ripple.bouncycastle.util.arrays;

/**
 * this class implements the gmss signature scheme.
 */
public class gmsssigner
    implements messagesigner
{

    /**
     * instance of gmssparameterspec
     */
    //private gmssparameterspec gmssparameterspec;

    /**
     * instance of gmssutilities
     */
    private gmssutil gmssutil = new gmssutil();


    /**
     * the raw gmss public key
     */
    private byte[] pubkeybytes;

    /**
     * hash function for the construction of the authentication trees
     */
    private digest messdigesttrees;

    /**
     * the length of the hash function output
     */
    private int mdlength;

    /**
     * the number of tree layers
     */
    private int numlayer;

    /**
     * the hash function used by the ots
     */
    private digest messdigestots;

    /**
     * an instance of the winternitz one-time signature
     */
    private winternitzotsignature ots;

    /**
     * array of strings containing the name of the hash function used by the ots
     * and the corresponding provider name
     */
    private gmssdigestprovider digestprovider;

    /**
     * the current main tree and subtree indices
     */
    private int[] index;

    /**
     * array of the authentication paths for the current trees of all layers
     */
    private byte[][][] currentauthpaths;

    /**
     * the one-time signature of the roots of the current subtrees
     */
    private byte[][] subtreerootsig;


    /**
     * the gmssparameterset
     */
    private gmssparameters gmssps;

    /**
     * the prng
     */
    private gmssrandom gmssrandom;

    gmsskeyparameters key;

    // xxx needed? source of randomness
    private securerandom random;


    /**
     * the standard constructor tries to generate the merkletree algorithm
     * identifier with the corresponding oid.
     *
     * @param digest     the digest to use
     */
    // todo
    public gmsssigner(gmssdigestprovider digest)
    {
        digestprovider = digest;
        messdigesttrees = digest.get();
        messdigestots = messdigesttrees;
        mdlength = messdigesttrees.getdigestsize();
        gmssrandom = new gmssrandom(messdigesttrees);
    }

    public void init(boolean forsigning,
                     cipherparameters param)
    {

        if (forsigning)
        {
            if (param instanceof parameterswithrandom)
            {
                parameterswithrandom rparam = (parameterswithrandom)param;

                // xxx random needed?
                this.random = rparam.getrandom();
                this.key = (gmssprivatekeyparameters)rparam.getparameters();
                initsign();

            }
            else
            {

                this.random = new securerandom();
                this.key = (gmssprivatekeyparameters)param;
                initsign();
            }
        }
        else
        {
            this.key = (gmsspublickeyparameters)param;
            initverify();

        }

    }


    /**
     * initializes the signature algorithm for signing a message.
     */
    private void initsign()
    {
        messdigesttrees.reset();
        // set private key and take from it ots key, auth, tree and key
        // counter, rootsign
        gmssprivatekeyparameters gmssprivatekey = (gmssprivatekeyparameters)key;

        if (gmssprivatekey.isused())
        {
            throw new illegalstateexception("private key already used");
        }

        // check if last signature has been generated
        if (gmssprivatekey.getindex(0) >= gmssprivatekey.getnumleafs(0))
        {
            throw new illegalstateexception("no more signatures can be generated");
        }

        // get parameterset
        this.gmssps = gmssprivatekey.getparameters();
        // get numlayer
        this.numlayer = gmssps.getnumoflayers();

        // get ots instance of lowest layer
        byte[] seed = gmssprivatekey.getcurrentseeds()[numlayer - 1];
        byte[] otsseed = new byte[mdlength];
        byte[] dummy = new byte[mdlength];
        system.arraycopy(seed, 0, dummy, 0, mdlength);
        otsseed = gmssrandom.nextseed(dummy); // securerandom.nextbytes(currentseeds[currentseeds.length-1]);securerandom.nextbytes(otsseed);
        this.ots = new winternitzotsignature(otsseed, digestprovider.get(), gmssps.getwinternitzparameter()[numlayer - 1]);

        byte[][][] helpcurrentauthpaths = gmssprivatekey.getcurrentauthpaths();
        currentauthpaths = new byte[numlayer][][];

        // copy the main tree authentication path
        for (int j = 0; j < numlayer; j++)
        {
            currentauthpaths[j] = new byte[helpcurrentauthpaths[j].length][mdlength];
            for (int i = 0; i < helpcurrentauthpaths[j].length; i++)
            {
                system.arraycopy(helpcurrentauthpaths[j][i], 0, currentauthpaths[j][i], 0, mdlength);
            }
        }

        // copy index
        index = new int[numlayer];
        system.arraycopy(gmssprivatekey.getindex(), 0, index, 0, numlayer);

        // copy subtreerootsig
        byte[] helpsubtreerootsig;
        subtreerootsig = new byte[numlayer - 1][];
        for (int i = 0; i < numlayer - 1; i++)
        {
            helpsubtreerootsig = gmssprivatekey.getsubtreerootsig(i);
            subtreerootsig[i] = new byte[helpsubtreerootsig.length];
            system.arraycopy(helpsubtreerootsig, 0, subtreerootsig[i], 0, helpsubtreerootsig.length);
        }

        gmssprivatekey.markused();
    }

    /**
     * signs a message.
     * <p/>
     *
     * @return the signature.
     */
    public byte[] generatesignature(byte[] message)
    {

        byte[] otssig = new byte[mdlength];
        byte[] authpathbytes;
        byte[] indexbytes;

        otssig = ots.getsignature(message);

        // get concatenated lowest layer tree authentication path
        authpathbytes = gmssutil.concatenatearray(currentauthpaths[numlayer - 1]);

        // put lowest layer index into a byte array
        indexbytes = gmssutil.inttobyteslittleendian(index[numlayer - 1]);

        // create first part of gmss signature
        byte[] gmsssigfirstpart = new byte[indexbytes.length + otssig.length + authpathbytes.length];
        system.arraycopy(indexbytes, 0, gmsssigfirstpart, 0, indexbytes.length);
        system.arraycopy(otssig, 0, gmsssigfirstpart, indexbytes.length, otssig.length);
        system.arraycopy(authpathbytes, 0, gmsssigfirstpart, (indexbytes.length + otssig.length), authpathbytes.length);
        // --- end first part

        // --- next parts of the signature
        // create initial array with length 0 for iteration
        byte[] gmsssignextpart = new byte[0];

        for (int i = numlayer - 1 - 1; i >= 0; i--)
        {

            // get concatenated next tree authentication path
            authpathbytes = gmssutil.concatenatearray(currentauthpaths[i]);

            // put next tree index into a byte array
            indexbytes = gmssutil.inttobyteslittleendian(index[i]);

            // create next part of gmss signature

            // create help array and copy actual gmsssig into it
            byte[] helpgmsssig = new byte[gmsssignextpart.length];
            system.arraycopy(gmsssignextpart, 0, helpgmsssig, 0, gmsssignextpart.length);
            // adjust length of gmsssignextpart for adding next part
            gmsssignextpart = new byte[helpgmsssig.length + indexbytes.length + subtreerootsig[i].length + authpathbytes.length];

            // copy old data (help array) and new data in gmsssignextpart
            system.arraycopy(helpgmsssig, 0, gmsssignextpart, 0, helpgmsssig.length);
            system.arraycopy(indexbytes, 0, gmsssignextpart, helpgmsssig.length, indexbytes.length);
            system.arraycopy(subtreerootsig[i], 0, gmsssignextpart, (helpgmsssig.length + indexbytes.length), subtreerootsig[i].length);
            system.arraycopy(authpathbytes, 0, gmsssignextpart, (helpgmsssig.length + indexbytes.length + subtreerootsig[i].length), authpathbytes.length);

        }
        // --- end next parts

        // concatenate the two parts of the gmss signature
        byte[] gmsssig = new byte[gmsssigfirstpart.length + gmsssignextpart.length];
        system.arraycopy(gmsssigfirstpart, 0, gmsssig, 0, gmsssigfirstpart.length);
        system.arraycopy(gmsssignextpart, 0, gmsssig, gmsssigfirstpart.length, gmsssignextpart.length);

        // return the gmss signature
        return gmsssig;
    }

    /**
     * initializes the signature algorithm for verifying a signature.
     */
    private void initverify()
    {
        messdigesttrees.reset();

        gmsspublickeyparameters gmsspublickey = (gmsspublickeyparameters)key;
        pubkeybytes = gmsspublickey.getpublickey();
        gmssps = gmsspublickey.getparameters();
        // get numlayer
        this.numlayer = gmssps.getnumoflayers();


    }

    /**
     * this function verifies the signature of the message that has been
     * updated, with the aid of the public key.
     *
     * @param message the message
     * @param signature the signature associated with the message
     * @return true if the signature has been verified, false otherwise.
     */
    public boolean verifysignature(byte[] message, byte[] signature)
    {

        boolean success = false;
        // int halfsiglength = signature.length >>> 1;
        messdigestots.reset();
        winternitzotsverify otsverify;
        int otssiglength;

        byte[] help = message;

        byte[] otssig;
        byte[] otspublickey;
        byte[][] authpath;
        byte[] dest;
        int nextentry = 0;
        int index;
        // verify signature

        // --- begin with message = 'message that was signed'
        // and then in each step message = subtree root
        for (int j = numlayer - 1; j >= 0; j--)
        {
            otsverify = new winternitzotsverify(digestprovider.get(), gmssps.getwinternitzparameter()[j]);
            otssiglength = otsverify.getsignaturelength();

            message = help;
            // get the subtree index
            index = gmssutil.bytestointlittleendian(signature, nextentry);

            // 4 is the number of bytes in integer
            nextentry += 4;

            // get one-time signature
            otssig = new byte[otssiglength];
            system.arraycopy(signature, nextentry, otssig, 0, otssiglength);
            nextentry += otssiglength;

            // compute public ots key from the one-time signature
            otspublickey = otsverify.verify(message, otssig);

            // test if otssignature is correct
            if (otspublickey == null)
            {
                system.err.println("ots public key is null in gmsssignature.verify");
                return false;
            }

            // get authentication path from the signature
            authpath = new byte[gmssps.getheightoftrees()[j]][mdlength];
            for (int i = 0; i < authpath.length; i++)
            {
                system.arraycopy(signature, nextentry, authpath[i], 0, mdlength);
                nextentry = nextentry + mdlength;
            }

            // compute the root of the subtree from the authentication path
            help = new byte[mdlength];

            help = otspublickey;

            int count = 1 << authpath.length;
            count = count + index;

            for (int i = 0; i < authpath.length; i++)
            {
                dest = new byte[mdlength << 1];

                if ((count % 2) == 0)
                {
                    system.arraycopy(help, 0, dest, 0, mdlength);
                    system.arraycopy(authpath[i], 0, dest, mdlength, mdlength);
                    count = count / 2;
                }
                else
                {
                    system.arraycopy(authpath[i], 0, dest, 0, mdlength);
                    system.arraycopy(help, 0, dest, mdlength, help.length);
                    count = (count - 1) / 2;
                }
                messdigesttrees.update(dest, 0, dest.length);
                help = new byte[messdigesttrees.getdigestsize()];
                messdigesttrees.dofinal(help, 0);
            }
        }

        // now help contains the root of the maintree

        // test if help is equal to the gmss public key
        if (arrays.areequal(pubkeybytes, help))
        {
            success = true;
        }

        return success;
    }


}