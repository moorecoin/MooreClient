package org.ripple.bouncycastle.pqc.asn1;

import java.math.biginteger;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.pqc.crypto.gmss.gmssleaf;
import org.ripple.bouncycastle.pqc.crypto.gmss.gmssparameters;
import org.ripple.bouncycastle.pqc.crypto.gmss.gmssrootcalc;
import org.ripple.bouncycastle.pqc.crypto.gmss.gmssrootsig;
import org.ripple.bouncycastle.pqc.crypto.gmss.treehash;

public class gmssprivatekey
    extends asn1object
{
    private asn1primitive primitive;

    private gmssprivatekey(asn1sequence mtsprivatekey)
    {
        // --- decode <index>.
        asn1sequence indexpart = (asn1sequence)mtsprivatekey.getobjectat(0);
        int[] index = new int[indexpart.size()];
        for (int i = 0; i < indexpart.size(); i++)
        {
            index[i] = checkbigintegerinintrange(indexpart.getobjectat(i));
        }

        // --- decode <curseeds>.
        asn1sequence curseedspart = (asn1sequence)mtsprivatekey.getobjectat(1);
        byte[][] curseeds = new byte[curseedspart.size()][];
        for (int i = 0; i < curseeds.length; i++)
        {
            curseeds[i] = ((deroctetstring)curseedspart.getobjectat(i)).getoctets();
        }

        // --- decode <nextnextseeds>.
        asn1sequence nextnextseedspart = (asn1sequence)mtsprivatekey.getobjectat(2);
        byte[][] nextnextseeds = new byte[nextnextseedspart.size()][];
        for (int i = 0; i < nextnextseeds.length; i++)
        {
            nextnextseeds[i] = ((deroctetstring)nextnextseedspart.getobjectat(i)).getoctets();
        }

        // --- decode <curauth>.
        asn1sequence curauthpart0 = (asn1sequence)mtsprivatekey.getobjectat(3);
        asn1sequence curauthpart1;

        byte[][][] curauth = new byte[curauthpart0.size()][][];
        for (int i = 0; i < curauth.length; i++)
        {
            curauthpart1 = (asn1sequence)curauthpart0.getobjectat(i);
            curauth[i] = new byte[curauthpart1.size()][];
            for (int j = 0; j < curauth[i].length; j++)
            {
                curauth[i][j] = ((deroctetstring)curauthpart1.getobjectat(j)).getoctets();
            }
        }

        // --- decode <nextauth>.
        asn1sequence nextauthpart0 = (asn1sequence)mtsprivatekey.getobjectat(4);
        asn1sequence nextauthpart1;

        byte[][][] nextauth = new byte[nextauthpart0.size()][][];
        for (int i = 0; i < nextauth.length; i++)
        {
            nextauthpart1 = (asn1sequence)nextauthpart0.getobjectat(i);
            nextauth[i] = new byte[nextauthpart1.size()][];
            for (int j = 0; j < nextauth[i].length; j++)
            {
                nextauth[i][j] = ((deroctetstring)nextauthpart1.getobjectat(j)).getoctets();
            }
        }

        // --- decode <curtreehash>.
        asn1sequence seqofcurtreehash0 = (asn1sequence)mtsprivatekey.getobjectat(5);
        asn1sequence seqofcurtreehash1;
        asn1sequence seqofcurtreehashstat;
        asn1sequence seqofcurtreehashbytes;
        asn1sequence seqofcurtreehashints;
        asn1sequence seqofcurtreehashstring;

        treehash[][] curtreehash = new treehash[seqofcurtreehash0.size()][];
        /*
        for (int i = 0; i < curtreehash.length; i++)
        {
            seqofcurtreehash1 = (asn1sequence)seqofcurtreehash0.getobjectat(i);
            curtreehash[i] = new treehash[seqofcurtreehash1.size()];
            for (int j = 0; j < curtreehash[i].length; j++)
            {
                seqofcurtreehashstat = (asn1sequence)seqofcurtreehash1.getobjectat(j);
                seqofcurtreehashstring = (asn1sequence)seqofcurtreehashstat
                    .getobjectat(0);
                seqofcurtreehashbytes = (asn1sequence)seqofcurtreehashstat
                    .getobjectat(1);
                seqofcurtreehashints = (asn1sequence)seqofcurtreehashstat
                    .getobjectat(2);

                string[] name = new string[2];
                name[0] = ((deria5string)seqofcurtreehashstring.getobjectat(0)).getstring();
                name[1] = ((deria5string)seqofcurtreehashstring.getobjectat(1)).getstring();

                int taillength = checkbigintegerinintrange(seqofcurtreehashints.getobjectat(1));
                byte[][] statbyte = new byte[3 + taillength][];
                statbyte[0] = ((deroctetstring)seqofcurtreehashbytes.getobjectat(0)).getoctets();

                if (statbyte[0].length == 0)
                { // if null was encoded
                    statbyte[0] = null;
                }

                statbyte[1] = ((deroctetstring)seqofcurtreehashbytes.getobjectat(1)).getoctets();
                statbyte[2] = ((deroctetstring)seqofcurtreehashbytes.getobjectat(2)).getoctets();
                for (int k = 0; k < taillength; k++)
                {
                    statbyte[3 + k] = ((deroctetstring)seqofcurtreehashbytes
                        .getobjectat(3 + k)).getoctets();
                }
                int[] statint = new int[6 + taillength];
                statint[0] = checkbigintegerinintrange(seqofcurtreehashints.getobjectat(0));
                statint[1] = taillength;
                statint[2] = checkbigintegerinintrange(seqofcurtreehashints.getobjectat(2));
                statint[3] = checkbigintegerinintrange(seqofcurtreehashints.getobjectat(3));
                statint[4] = checkbigintegerinintrange(seqofcurtreehashints.getobjectat(4));
                statint[5] = checkbigintegerinintrange(seqofcurtreehashints.getobjectat(5));
                for (int k = 0; k < taillength; k++)
                {
                    statint[6 + k] = checkbigintegerinintrange(seqofcurtreehashints.getobjectat(6 + k));
                }

                // todo: check if we can do better than throwing away name[1] !!!
                curtreehash[i][j] = new treehash(digestfactory.getdigest(name[0]).getclass(), statbyte, statint);
            }
        }


        // --- decode <nexttreehash>.
        asn1sequence seqofnexttreehash0 = (asn1sequence)mtsprivatekey.getobjectat(6);
        asn1sequence seqofnexttreehash1;
        asn1sequence seqofnexttreehashstat;
        asn1sequence seqofnexttreehashbytes;
        asn1sequence seqofnexttreehashints;
        asn1sequence seqofnexttreehashstring;

        treehash[][] nexttreehash = new treehash[seqofnexttreehash0.size()][];

        for (int i = 0; i < nexttreehash.length; i++)
        {
            seqofnexttreehash1 = (asn1sequence)seqofnexttreehash0.getobjectat(i);
            nexttreehash[i] = new treehash[seqofnexttreehash1.size()];
            for (int j = 0; j < nexttreehash[i].length; j++)
            {
                seqofnexttreehashstat = (asn1sequence)seqofnexttreehash1
                    .getobjectat(j);
                seqofnexttreehashstring = (asn1sequence)seqofnexttreehashstat
                    .getobjectat(0);
                seqofnexttreehashbytes = (asn1sequence)seqofnexttreehashstat
                    .getobjectat(1);
                seqofnexttreehashints = (asn1sequence)seqofnexttreehashstat
                    .getobjectat(2);

                string[] name = new string[2];
                name[0] = ((deria5string)seqofnexttreehashstring.getobjectat(0))
                    .getstring();
                name[1] = ((deria5string)seqofnexttreehashstring.getobjectat(1))
                    .getstring();

                int taillength = checkbigintegerinintrange(seqofnexttreehashints.getobjectat(1));

                byte[][] statbyte = new byte[3 + taillength][];
                statbyte[0] = ((deroctetstring)seqofnexttreehashbytes.getobjectat(0)).getoctets();
                if (statbyte[0].length == 0)
                { // if null was encoded
                    statbyte[0] = null;
                }

                statbyte[1] = ((deroctetstring)seqofnexttreehashbytes.getobjectat(1)).getoctets();
                statbyte[2] = ((deroctetstring)seqofnexttreehashbytes.getobjectat(2)).getoctets();
                for (int k = 0; k < taillength; k++)
                {
                    statbyte[3 + k] = ((deroctetstring)seqofnexttreehashbytes
                        .getobjectat(3 + k)).getoctets();
                }
                int[] statint = new int[6 + taillength];
                statint[0] = checkbigintegerinintrange(seqofnexttreehashints.getobjectat(0));

                statint[1] = taillength;
                statint[2] = checkbigintegerinintrange(seqofnexttreehashints.getobjectat(2));

                statint[3] = checkbigintegerinintrange(seqofnexttreehashints.getobjectat(3));

                statint[4] = checkbigintegerinintrange(seqofnexttreehashints.getobjectat(4));

                statint[5] = checkbigintegerinintrange(seqofnexttreehashints.getobjectat(5));

                for (int k = 0; k < taillength; k++)
                {
                    statint[6 + k] = checkbigintegerinintrange(seqofnexttreehashints.getobjectat(6 + k));

                }
                nexttreehash[i][j] = new treehash(digestfactory.getdigest(name[0]).getclass(), statbyte, statint);
            }
        }


        // --- decode <keep>.
        asn1sequence keeppart0 = (asn1sequence)mtsprivatekey.getobjectat(7);
        asn1sequence keeppart1;

        byte[][][] keep = new byte[keeppart0.size()][][];
        for (int i = 0; i < keep.length; i++)
        {
            keeppart1 = (asn1sequence)keeppart0.getobjectat(i);
            keep[i] = new byte[keeppart1.size()][];
            for (int j = 0; j < keep[i].length; j++)
            {
                keep[i][j] = ((deroctetstring)keeppart1.getobjectat(j)).getoctets();
            }
        }

        // --- decode <curstack>.
        asn1sequence curstackpart0 = (asn1sequence)mtsprivatekey.getobjectat(8);
        asn1sequence curstackpart1;

        vector[] curstack = new vector[curstackpart0.size()];
        for (int i = 0; i < curstack.length; i++)
        {
            curstackpart1 = (asn1sequence)curstackpart0.getobjectat(i);
            curstack[i] = new vector();
            for (int j = 0; j < curstackpart1.size(); j++)
            {
                curstack[i].addelement(((deroctetstring)curstackpart1.getobjectat(j)).getoctets());
            }
        }

        // --- decode <nextstack>.
        asn1sequence nextstackpart0 = (asn1sequence)mtsprivatekey.getobjectat(9);
        asn1sequence nextstackpart1;

        vector[] nextstack = new vector[nextstackpart0.size()];
        for (int i = 0; i < nextstack.length; i++)
        {
            nextstackpart1 = (asn1sequence)nextstackpart0.getobjectat(i);
            nextstack[i] = new vector();
            for (int j = 0; j < nextstackpart1.size(); j++)
            {
                nextstack[i].addelement(((deroctetstring)nextstackpart1
                    .getobjectat(j)).getoctets());
            }
        }

        // --- decode <curretain>.
        asn1sequence curretainpart0 = (asn1sequence)mtsprivatekey.getobjectat(10);
        asn1sequence curretainpart1;
        asn1sequence curretainpart2;

        vector[][] curretain = new vector[curretainpart0.size()][];
        for (int i = 0; i < curretain.length; i++)
        {
            curretainpart1 = (asn1sequence)curretainpart0.getobjectat(i);
            curretain[i] = new vector[curretainpart1.size()];
            for (int j = 0; j < curretain[i].length; j++)
            {
                curretainpart2 = (asn1sequence)curretainpart1.getobjectat(j);
                curretain[i][j] = new vector();
                for (int k = 0; k < curretainpart2.size(); k++)
                {
                    curretain[i][j]
                        .addelement(((deroctetstring)curretainpart2
                            .getobjectat(k)).getoctets());
                }
            }
        }

        // --- decode <nextretain>.
        asn1sequence nextretainpart0 = (asn1sequence)mtsprivatekey.getobjectat(11);
        asn1sequence nextretainpart1;
        asn1sequence nextretainpart2;

        vector[][] nextretain = new vector[nextretainpart0.size()][];
        for (int i = 0; i < nextretain.length; i++)
        {
            nextretainpart1 = (asn1sequence)nextretainpart0.getobjectat(i);
            nextretain[i] = new vector[nextretainpart1.size()];
            for (int j = 0; j < nextretain[i].length; j++)
            {
                nextretainpart2 = (asn1sequence)nextretainpart1.getobjectat(j);
                nextretain[i][j] = new vector();
                for (int k = 0; k < nextretainpart2.size(); k++)
                {
                    nextretain[i][j]
                        .addelement(((deroctetstring)nextretainpart2
                            .getobjectat(k)).getoctets());
                }
            }
        }

        // --- decode <nextnextleaf>.
        asn1sequence seqofleafs = (asn1sequence)mtsprivatekey.getobjectat(12);
        asn1sequence seqofleafstat;
        asn1sequence seqofleafbytes;
        asn1sequence seqofleafints;
        asn1sequence seqofleafstring;

        gmssleaf[] nextnextleaf = new gmssleaf[seqofleafs.size()];

        for (int i = 0; i < nextnextleaf.length; i++)
        {
            seqofleafstat = (asn1sequence)seqofleafs.getobjectat(i);
            // nextnextauth[i]= new byte[nextnextauthpart1.size()][];
            seqofleafstring = (asn1sequence)seqofleafstat.getobjectat(0);
            seqofleafbytes = (asn1sequence)seqofleafstat.getobjectat(1);
            seqofleafints = (asn1sequence)seqofleafstat.getobjectat(2);

            string[] name = new string[2];
            name[0] = ((deria5string)seqofleafstring.getobjectat(0)).getstring();
            name[1] = ((deria5string)seqofleafstring.getobjectat(1)).getstring();
            byte[][] statbyte = new byte[4][];
            statbyte[0] = ((deroctetstring)seqofleafbytes.getobjectat(0))
                .getoctets();
            statbyte[1] = ((deroctetstring)seqofleafbytes.getobjectat(1))
                .getoctets();
            statbyte[2] = ((deroctetstring)seqofleafbytes.getobjectat(2))
                .getoctets();
            statbyte[3] = ((deroctetstring)seqofleafbytes.getobjectat(3))
                .getoctets();
            int[] statint = new int[4];
            statint[0] = checkbigintegerinintrange(seqofleafints.getobjectat(0));
            statint[1] = checkbigintegerinintrange(seqofleafints.getobjectat(1));
            statint[2] = checkbigintegerinintrange(seqofleafints.getobjectat(2));
            statint[3] = checkbigintegerinintrange(seqofleafints.getobjectat(3));
            nextnextleaf[i] = new gmssleaf(digestfactory.getdigest(name[0]).getclass(), statbyte, statint);
        }

        // --- decode <upperleaf>.
        asn1sequence seqofupperleafs = (asn1sequence)mtsprivatekey.getobjectat(13);
        asn1sequence seqofupperleafstat;
        asn1sequence seqofupperleafbytes;
        asn1sequence seqofupperleafints;
        asn1sequence seqofupperleafstring;

        gmssleaf[] upperleaf = new gmssleaf[seqofupperleafs.size()];

        for (int i = 0; i < upperleaf.length; i++)
        {
            seqofupperleafstat = (asn1sequence)seqofupperleafs.getobjectat(i);
            seqofupperleafstring = (asn1sequence)seqofupperleafstat.getobjectat(0);
            seqofupperleafbytes = (asn1sequence)seqofupperleafstat.getobjectat(1);
            seqofupperleafints = (asn1sequence)seqofupperleafstat.getobjectat(2);

            string[] name = new string[2];
            name[0] = ((deria5string)seqofupperleafstring.getobjectat(0)).getstring();
            name[1] = ((deria5string)seqofupperleafstring.getobjectat(1)).getstring();
            byte[][] statbyte = new byte[4][];
            statbyte[0] = ((deroctetstring)seqofupperleafbytes.getobjectat(0))
                .getoctets();
            statbyte[1] = ((deroctetstring)seqofupperleafbytes.getobjectat(1))
                .getoctets();
            statbyte[2] = ((deroctetstring)seqofupperleafbytes.getobjectat(2))
                .getoctets();
            statbyte[3] = ((deroctetstring)seqofupperleafbytes.getobjectat(3))
                .getoctets();
            int[] statint = new int[4];
            statint[0] = checkbigintegerinintrange(seqofupperleafints.getobjectat(0));
            statint[1] = checkbigintegerinintrange(seqofupperleafints.getobjectat(1));
            statint[2] = checkbigintegerinintrange(seqofupperleafints.getobjectat(2));
            statint[3] = checkbigintegerinintrange(seqofupperleafints.getobjectat(3));
            upperleaf[i] = new gmssleaf(digestfactory.getdigest(name[0]).getclass(), statbyte, statint);
        }

        // --- decode <uppertreehashleaf>.
        asn1sequence seqofupperthleafs = (asn1sequence)mtsprivatekey.getobjectat(14);
        asn1sequence seqofupperthleafstat;
        asn1sequence seqofupperthleafbytes;
        asn1sequence seqofupperthleafints;
        asn1sequence seqofupperthleafstring;

        gmssleaf[] upperthleaf = new gmssleaf[seqofupperthleafs.size()];

        for (int i = 0; i < upperthleaf.length; i++)
        {
            seqofupperthleafstat = (asn1sequence)seqofupperthleafs.getobjectat(i);
            seqofupperthleafstring = (asn1sequence)seqofupperthleafstat.getobjectat(0);
            seqofupperthleafbytes = (asn1sequence)seqofupperthleafstat.getobjectat(1);
            seqofupperthleafints = (asn1sequence)seqofupperthleafstat.getobjectat(2);

            string[] name = new string[2];
            name[0] = ((deria5string)seqofupperthleafstring.getobjectat(0))
                .getstring();
            name[1] = ((deria5string)seqofupperthleafstring.getobjectat(1))
                .getstring();
            byte[][] statbyte = new byte[4][];
            statbyte[0] = ((deroctetstring)seqofupperthleafbytes.getobjectat(0))
                .getoctets();
            statbyte[1] = ((deroctetstring)seqofupperthleafbytes.getobjectat(1))
                .getoctets();
            statbyte[2] = ((deroctetstring)seqofupperthleafbytes.getobjectat(2))
                .getoctets();
            statbyte[3] = ((deroctetstring)seqofupperthleafbytes.getobjectat(3))
                .getoctets();
            int[] statint = new int[4];
            statint[0] = checkbigintegerinintrange(seqofupperthleafints.getobjectat(0));
            statint[1] = checkbigintegerinintrange(seqofupperthleafints.getobjectat(1));
            statint[2] = checkbigintegerinintrange(seqofupperthleafints.getobjectat(2));
            statint[3] = checkbigintegerinintrange(seqofupperthleafints.getobjectat(3));
            upperthleaf[i] = new gmssleaf(digestfactory.getdigest(name[0]).getclass(), statbyte, statint);
        }

        // --- decode <mintreehash>.
        asn1sequence mintreehashpart = (asn1sequence)mtsprivatekey.getobjectat(15);
        int[] mintreehash = new int[mintreehashpart.size()];
        for (int i = 0; i < mintreehashpart.size(); i++)
        {
            mintreehash[i] = checkbigintegerinintrange(mintreehashpart.getobjectat(i));
        }

        // --- decode <nextroot>.
        asn1sequence seqofnextroots = (asn1sequence)mtsprivatekey.getobjectat(16);
        byte[][] nextroot = new byte[seqofnextroots.size()][];
        for (int i = 0; i < nextroot.length; i++)
        {
            nextroot[i] = ((deroctetstring)seqofnextroots.getobjectat(i))
                .getoctets();
        }

        // --- decode <nextnextroot>.
        asn1sequence seqofnextnextroot = (asn1sequence)mtsprivatekey.getobjectat(17);
        asn1sequence seqofnextnextrootstat;
        asn1sequence seqofnextnextrootbytes;
        asn1sequence seqofnextnextrootints;
        asn1sequence seqofnextnextrootstring;
        asn1sequence seqofnextnextroottreeh;
        asn1sequence seqofnextnextrootretain;

        gmssrootcalc[] nextnextroot = new gmssrootcalc[seqofnextnextroot.size()];

        for (int i = 0; i < nextnextroot.length; i++)
        {
            seqofnextnextrootstat = (asn1sequence)seqofnextnextroot.getobjectat(i);
            seqofnextnextrootstring = (asn1sequence)seqofnextnextrootstat
                .getobjectat(0);
            seqofnextnextrootbytes = (asn1sequence)seqofnextnextrootstat
                .getobjectat(1);
            seqofnextnextrootints = (asn1sequence)seqofnextnextrootstat.getobjectat(2);
            seqofnextnextroottreeh = (asn1sequence)seqofnextnextrootstat
                .getobjectat(3);
            seqofnextnextrootretain = (asn1sequence)seqofnextnextrootstat
                .getobjectat(4);

            // decode treehash of nextnextroot
            // ---------------------------------
            asn1sequence seqofnextnextroottreehstat;
            asn1sequence seqofnextnextroottreehbytes;
            asn1sequence seqofnextnextroottreehints;
            asn1sequence seqofnextnextroottreehstring;

            treehash[] nnrtreehash = new treehash[seqofnextnextroottreeh.size()];

            for (int k = 0; k < nnrtreehash.length; k++)
            {
                seqofnextnextroottreehstat = (asn1sequence)seqofnextnextroottreeh
                    .getobjectat(k);
                seqofnextnextroottreehstring = (asn1sequence)seqofnextnextroottreehstat
                    .getobjectat(0);
                seqofnextnextroottreehbytes = (asn1sequence)seqofnextnextroottreehstat
                    .getobjectat(1);
                seqofnextnextroottreehints = (asn1sequence)seqofnextnextroottreehstat
                    .getobjectat(2);

                string[] name = new string[2];
                name[0] = ((deria5string)seqofnextnextroottreehstring.getobjectat(0))
                    .getstring();
                name[1] = ((deria5string)seqofnextnextroottreehstring.getobjectat(1))
                    .getstring();

                int taillength = checkbigintegerinintrange(seqofnextnextroottreehints.getobjectat(1));

                byte[][] statbyte = new byte[3 + taillength][];
                statbyte[0] = ((deroctetstring)seqofnextnextroottreehbytes
                    .getobjectat(0)).getoctets();
                if (statbyte[0].length == 0)
                { // if null was encoded
                    statbyte[0] = null;
                }

                statbyte[1] = ((deroctetstring)seqofnextnextroottreehbytes
                    .getobjectat(1)).getoctets();
                statbyte[2] = ((deroctetstring)seqofnextnextroottreehbytes
                    .getobjectat(2)).getoctets();
                for (int j = 0; j < taillength; j++)
                {
                    statbyte[3 + j] = ((deroctetstring)seqofnextnextroottreehbytes
                        .getobjectat(3 + j)).getoctets();
                }
                int[] statint = new int[6 + taillength];
                statint[0] = checkbigintegerinintrange(seqofnextnextroottreehints.getobjectat(0));

                statint[1] = taillength;
                statint[2] = checkbigintegerinintrange(seqofnextnextroottreehints.getobjectat(2));

                statint[3] = checkbigintegerinintrange(seqofnextnextroottreehints.getobjectat(3));

                statint[4] = checkbigintegerinintrange(seqofnextnextroottreehints.getobjectat(4));

                statint[5] = checkbigintegerinintrange(seqofnextnextroottreehints.getobjectat(5));

                for (int j = 0; j < taillength; j++)
                {
                    statint[6 + j] = checkbigintegerinintrange(seqofnextnextroottreehints
                        .getobjectat(6 + j));
                }
                nnrtreehash[k] = new treehash(digestfactory.getdigest(name[0]).getclass(), statbyte, statint);
            }
            // ---------------------------------

            // decode retain of nextnextroot
            // ---------------------------------
            // asn1sequence seqofnextnextrootretainpart0 =
            // (asn1sequence)seqofnextnextrootretain.get(0);
            asn1sequence seqofnextnextrootretainpart1;

            vector[] nnrretain = new vector[seqofnextnextrootretain.size()];
            for (int j = 0; j < nnrretain.length; j++)
            {
                seqofnextnextrootretainpart1 = (asn1sequence)seqofnextnextrootretain
                    .getobjectat(j);
                nnrretain[j] = new vector();
                for (int k = 0; k < seqofnextnextrootretainpart1.size(); k++)
                {
                    nnrretain[j]
                        .addelement(((deroctetstring)seqofnextnextrootretainpart1
                            .getobjectat(k)).getoctets());
                }
            }
            // ---------------------------------

            string[] name = new string[2];
            name[0] = ((deria5string)seqofnextnextrootstring.getobjectat(0))
                .getstring();
            name[1] = ((deria5string)seqofnextnextrootstring.getobjectat(1))
                .getstring();

            int heightoftree = checkbigintegerinintrange(seqofnextnextrootints.getobjectat(0));
            int taillength = checkbigintegerinintrange(seqofnextnextrootints.getobjectat(7));
            byte[][] statbyte = new byte[1 + heightoftree + taillength][];
            statbyte[0] = ((deroctetstring)seqofnextnextrootbytes.getobjectat(0))
                .getoctets();
            for (int j = 0; j < heightoftree; j++)
            {
                statbyte[1 + j] = ((deroctetstring)seqofnextnextrootbytes
                    .getobjectat(1 + j)).getoctets();
            }
            for (int j = 0; j < taillength; j++)
            {
                statbyte[1 + heightoftree + j] = ((deroctetstring)seqofnextnextrootbytes
                    .getobjectat(1 + heightoftree + j)).getoctets();
            }
            int[] statint = new int[8 + heightoftree + taillength];
            statint[0] = heightoftree;
            statint[1] = checkbigintegerinintrange(seqofnextnextrootints.getobjectat(1));
            statint[2] = checkbigintegerinintrange(seqofnextnextrootints.getobjectat(2));
            statint[3] = checkbigintegerinintrange(seqofnextnextrootints.getobjectat(3));
            statint[4] = checkbigintegerinintrange(seqofnextnextrootints.getobjectat(4));
            statint[5] = checkbigintegerinintrange(seqofnextnextrootints.getobjectat(5));
            statint[6] = checkbigintegerinintrange(seqofnextnextrootints.getobjectat(6));
            statint[7] = taillength;
            for (int j = 0; j < heightoftree; j++)
            {
                statint[8 + j] = checkbigintegerinintrange(seqofnextnextrootints.getobjectat(8 + j));
            }
            for (int j = 0; j < taillength; j++)
            {
                statint[8 + heightoftree + j] = checkbigintegerinintrange(seqofnextnextrootints.getobjectat(8
                    + heightoftree + j));
            }
            nextnextroot[i] = new gmssrootcalc(digestfactory.getdigest(name[0]).getclass(), statbyte, statint,
                nnrtreehash, nnrretain);
        }

        // --- decode <currootsig>.
        asn1sequence seqofcurrootsig = (asn1sequence)mtsprivatekey.getobjectat(18);
        byte[][] currootsig = new byte[seqofcurrootsig.size()][];
        for (int i = 0; i < currootsig.length; i++)
        {
            currootsig[i] = ((deroctetstring)seqofcurrootsig.getobjectat(i))
                .getoctets();
        }

        // --- decode <nextrootsig>.
        asn1sequence seqofnextrootsigs = (asn1sequence)mtsprivatekey.getobjectat(19);
        asn1sequence seqofnrsstats;
        asn1sequence seqofnrsstrings;
        asn1sequence seqofnrsints;
        asn1sequence seqofnrsbytes;

        gmssrootsig[] nextrootsig = new gmssrootsig[seqofnextrootsigs.size()];

        for (int i = 0; i < nextrootsig.length; i++)
        {
            seqofnrsstats = (asn1sequence)seqofnextrootsigs.getobjectat(i);
            // nextnextauth[i]= new byte[nextnextauthpart1.size()][];
            seqofnrsstrings = (asn1sequence)seqofnrsstats.getobjectat(0);
            seqofnrsbytes = (asn1sequence)seqofnrsstats.getobjectat(1);
            seqofnrsints = (asn1sequence)seqofnrsstats.getobjectat(2);

            string[] name = new string[2];
            name[0] = ((deria5string)seqofnrsstrings.getobjectat(0)).getstring();
            name[1] = ((deria5string)seqofnrsstrings.getobjectat(1)).getstring();
            byte[][] statbyte = new byte[5][];
            statbyte[0] = ((deroctetstring)seqofnrsbytes.getobjectat(0))
                .getoctets();
            statbyte[1] = ((deroctetstring)seqofnrsbytes.getobjectat(1))
                .getoctets();
            statbyte[2] = ((deroctetstring)seqofnrsbytes.getobjectat(2))
                .getoctets();
            statbyte[3] = ((deroctetstring)seqofnrsbytes.getobjectat(3))
                .getoctets();
            statbyte[4] = ((deroctetstring)seqofnrsbytes.getobjectat(4))
                .getoctets();
            int[] statint = new int[9];
            statint[0] = checkbigintegerinintrange(seqofnrsints.getobjectat(0));
            statint[1] = checkbigintegerinintrange(seqofnrsints.getobjectat(1));
            statint[2] = checkbigintegerinintrange(seqofnrsints.getobjectat(2));
            statint[3] = checkbigintegerinintrange(seqofnrsints.getobjectat(3));
            statint[4] = checkbigintegerinintrange(seqofnrsints.getobjectat(4));
            statint[5] = checkbigintegerinintrange(seqofnrsints.getobjectat(5));
            statint[6] = checkbigintegerinintrange(seqofnrsints.getobjectat(6));
            statint[7] = checkbigintegerinintrange(seqofnrsints.getobjectat(7));
            statint[8] = checkbigintegerinintrange(seqofnrsints.getobjectat(8));
            nextrootsig[i] = new gmssrootsig(digestfactory.getdigest(name[0]).getclass(), statbyte, statint);
        }

        // --- decode <name>.

        // todo: really check, why there are multiple algorithms, we only
        //       use the first one!!!
        asn1sequence namepart = (asn1sequence)mtsprivatekey.getobjectat(20);
        string[] name = new string[namepart.size()];
        for (int i = 0; i < name.length; i++)
        {
            name[i] = ((deria5string)namepart.getobjectat(i)).getstring();
        }
        */
    }

    public gmssprivatekey(int[] index, byte[][] currentseed,
                          byte[][] nextnextseed, byte[][][] currentauthpath,
                          byte[][][] nextauthpath, treehash[][] currenttreehash,
                          treehash[][] nexttreehash, vector[] currentstack,
                          vector[] nextstack, vector[][] currentretain,
                          vector[][] nextretain, byte[][][] keep, gmssleaf[] nextnextleaf,
                          gmssleaf[] upperleaf, gmssleaf[] uppertreehashleaf,
                          int[] mintreehash, byte[][] nextroot, gmssrootcalc[] nextnextroot,
                          byte[][] currentrootsig, gmssrootsig[] nextrootsig,
                          gmssparameters gmssparameterset, algorithmidentifier digestalg)
    {
        algorithmidentifier[] names = new algorithmidentifier[] { digestalg };
        this.primitive = encode(index, currentseed, nextnextseed, currentauthpath, nextauthpath, keep, currenttreehash, nexttreehash, currentstack, nextstack, currentretain, nextretain, nextnextleaf, upperleaf, uppertreehashleaf, mintreehash, nextroot, nextnextroot, currentrootsig, nextrootsig, gmssparameterset, names);
    }


    // todo: change method signature to something more integrated into bouncycastle

    /**
     * @param index             tree indices
     * @param currentseeds      seed for the generation of private ots keys for the
     *                          current subtrees (tree)
     * @param nextnextseeds     seed for the generation of private ots keys for the
     *                          subtrees after next (tree++)
     * @param currentauthpaths  array of current authentication paths (authpath)
     * @param nextauthpaths     array of next authentication paths (authpath+)
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
     * @param algorithms        an array of algorithm identifiers, containing the hash function details
     */
    private asn1primitive encode(int[] index, byte[][] currentseeds,
                                byte[][] nextnextseeds, byte[][][] currentauthpaths,
                                byte[][][] nextauthpaths, byte[][][] keep,
                                treehash[][] currenttreehash, treehash[][] nexttreehash,
                                vector[] currentstack, vector[] nextstack,
                                vector[][] currentretain, vector[][] nextretain,
                                gmssleaf[] nextnextleaf, gmssleaf[] upperleaf,
                                gmssleaf[] uppertreehashleaf, int[] mintreehash, byte[][] nextroot,
                                gmssrootcalc[] nextnextroot, byte[][] currentrootsig,
                                gmssrootsig[] nextrootsig, gmssparameters gmssparameterset,
                                algorithmidentifier[] algorithms)
    {

        asn1encodablevector result = new asn1encodablevector();

        // --- encode <index>.
        asn1encodablevector indexpart = new asn1encodablevector();
        for (int i = 0; i < index.length; i++)
        {
            indexpart.add(new asn1integer(index[i]));
        }
        result.add(new dersequence(indexpart));

        // --- encode <curseeds>.
        asn1encodablevector curseedspart = new asn1encodablevector();
        for (int i = 0; i < currentseeds.length; i++)
        {
            curseedspart.add(new deroctetstring(currentseeds[i]));
        }
        result.add(new dersequence(curseedspart));

        // --- encode <nextnextseeds>.
        asn1encodablevector nextnextseedspart = new asn1encodablevector();
        for (int i = 0; i < nextnextseeds.length; i++)
        {
            nextnextseedspart.add(new deroctetstring(nextnextseeds[i]));
        }
        result.add(new dersequence(nextnextseedspart));

        // --- encode <curauth>.
        asn1encodablevector curauthpart0 = new asn1encodablevector();
        asn1encodablevector curauthpart1 = new asn1encodablevector();
        for (int i = 0; i < currentauthpaths.length; i++)
        {
            for (int j = 0; j < currentauthpaths[i].length; j++)
            {
                curauthpart0.add(new deroctetstring(currentauthpaths[i][j]));
            }
            curauthpart1.add(new dersequence(curauthpart0));
            curauthpart0 = new asn1encodablevector();
        }
        result.add(new dersequence(curauthpart1));

        // --- encode <nextauth>.
        asn1encodablevector nextauthpart0 = new asn1encodablevector();
        asn1encodablevector nextauthpart1 = new asn1encodablevector();
        for (int i = 0; i < nextauthpaths.length; i++)
        {
            for (int j = 0; j < nextauthpaths[i].length; j++)
            {
                nextauthpart0.add(new deroctetstring(nextauthpaths[i][j]));
            }
            nextauthpart1.add(new dersequence(nextauthpart0));
            nextauthpart0 = new asn1encodablevector();
        }
        result.add(new dersequence(nextauthpart1));

        // --- encode <curtreehash>.
        asn1encodablevector seqoftreehash0 = new asn1encodablevector();
        asn1encodablevector seqoftreehash1 = new asn1encodablevector();
        asn1encodablevector seqofstat = new asn1encodablevector();
        asn1encodablevector seqofbyte = new asn1encodablevector();
        asn1encodablevector seqofint = new asn1encodablevector();

        for (int i = 0; i < currenttreehash.length; i++)
        {
            for (int j = 0; j < currenttreehash[i].length; j++)
            {
                seqofstat.add(new dersequence(algorithms[0]));

                int taillength = currenttreehash[i][j].getstatint()[1];

                seqofbyte.add(new deroctetstring(currenttreehash[i][j]
                    .getstatbyte()[0]));
                seqofbyte.add(new deroctetstring(currenttreehash[i][j]
                    .getstatbyte()[1]));
                seqofbyte.add(new deroctetstring(currenttreehash[i][j]
                    .getstatbyte()[2]));
                for (int k = 0; k < taillength; k++)
                {
                    seqofbyte.add(new deroctetstring(currenttreehash[i][j]
                        .getstatbyte()[3 + k]));
                }
                seqofstat.add(new dersequence(seqofbyte));
                seqofbyte = new asn1encodablevector();

                seqofint.add(new asn1integer(
                    currenttreehash[i][j].getstatint()[0]));
                seqofint.add(new asn1integer(taillength));
                seqofint.add(new asn1integer(
                    currenttreehash[i][j].getstatint()[2]));
                seqofint.add(new asn1integer(
                    currenttreehash[i][j].getstatint()[3]));
                seqofint.add(new asn1integer(
                    currenttreehash[i][j].getstatint()[4]));
                seqofint.add(new asn1integer(
                    currenttreehash[i][j].getstatint()[5]));
                for (int k = 0; k < taillength; k++)
                {
                    seqofint.add(new asn1integer(currenttreehash[i][j]
                        .getstatint()[6 + k]));
                }
                seqofstat.add(new dersequence(seqofint));
                seqofint = new asn1encodablevector();

                seqoftreehash1.add(new dersequence(seqofstat));
                seqofstat = new asn1encodablevector();
            }
            seqoftreehash0.add(new dersequence(seqoftreehash1));
            seqoftreehash1 = new asn1encodablevector();
        }
        result.add(new dersequence(seqoftreehash0));

        // --- encode <nexttreehash>.
        seqoftreehash0 = new asn1encodablevector();
        seqoftreehash1 = new asn1encodablevector();
        seqofstat = new asn1encodablevector();
        seqofbyte = new asn1encodablevector();
        seqofint = new asn1encodablevector();

        for (int i = 0; i < nexttreehash.length; i++)
        {
            for (int j = 0; j < nexttreehash[i].length; j++)
            {
                seqofstat.add(new dersequence(algorithms[0]));

                int taillength = nexttreehash[i][j].getstatint()[1];

                seqofbyte.add(new deroctetstring(nexttreehash[i][j]
                    .getstatbyte()[0]));
                seqofbyte.add(new deroctetstring(nexttreehash[i][j]
                    .getstatbyte()[1]));
                seqofbyte.add(new deroctetstring(nexttreehash[i][j]
                    .getstatbyte()[2]));
                for (int k = 0; k < taillength; k++)
                {
                    seqofbyte.add(new deroctetstring(nexttreehash[i][j]
                        .getstatbyte()[3 + k]));
                }
                seqofstat.add(new dersequence(seqofbyte));
                seqofbyte = new asn1encodablevector();

                seqofint
                    .add(new asn1integer(nexttreehash[i][j].getstatint()[0]));
                seqofint.add(new asn1integer(taillength));
                seqofint
                    .add(new asn1integer(nexttreehash[i][j].getstatint()[2]));
                seqofint
                    .add(new asn1integer(nexttreehash[i][j].getstatint()[3]));
                seqofint
                    .add(new asn1integer(nexttreehash[i][j].getstatint()[4]));
                seqofint
                    .add(new asn1integer(nexttreehash[i][j].getstatint()[5]));
                for (int k = 0; k < taillength; k++)
                {
                    seqofint.add(new asn1integer(nexttreehash[i][j]
                        .getstatint()[6 + k]));
                }
                seqofstat.add(new dersequence(seqofint));
                seqofint = new asn1encodablevector();

                seqoftreehash1.add(new dersequence(seqofstat));
                seqofstat = new asn1encodablevector();
            }
            seqoftreehash0.add(new dersequence(new dersequence(seqoftreehash1)));
            seqoftreehash1 = new asn1encodablevector();
        }
        result.add(new dersequence(seqoftreehash0));

        // --- encode <keep>.
        asn1encodablevector keeppart0 = new asn1encodablevector();
        asn1encodablevector keeppart1 = new asn1encodablevector();
        for (int i = 0; i < keep.length; i++)
        {
            for (int j = 0; j < keep[i].length; j++)
            {
                keeppart0.add(new deroctetstring(keep[i][j]));
            }
            keeppart1.add(new dersequence(keeppart0));
            keeppart0 = new asn1encodablevector();
        }
        result.add(new dersequence(keeppart1));

        // --- encode <curstack>.
        asn1encodablevector curstackpart0 = new asn1encodablevector();
        asn1encodablevector curstackpart1 = new asn1encodablevector();
        for (int i = 0; i < currentstack.length; i++)
        {
            for (int j = 0; j < currentstack[i].size(); j++)
            {
                curstackpart0.add(new deroctetstring((byte[])currentstack[i]
                    .elementat(j)));
            }
            curstackpart1.add(new dersequence(curstackpart0));
            curstackpart0 = new asn1encodablevector();
        }
        result.add(new dersequence(curstackpart1));

        // --- encode <nextstack>.
        asn1encodablevector nextstackpart0 = new asn1encodablevector();
        asn1encodablevector nextstackpart1 = new asn1encodablevector();
        for (int i = 0; i < nextstack.length; i++)
        {
            for (int j = 0; j < nextstack[i].size(); j++)
            {
                nextstackpart0.add(new deroctetstring((byte[])nextstack[i]
                    .elementat(j)));
            }
            nextstackpart1.add(new dersequence(nextstackpart0));
            nextstackpart0 = new asn1encodablevector();
        }
        result.add(new dersequence(nextstackpart1));

        // --- encode <curretain>.
        asn1encodablevector currentretainpart0 = new asn1encodablevector();
        asn1encodablevector currentretainpart1 = new asn1encodablevector();
        asn1encodablevector currentretainpart2 = new asn1encodablevector();
        for (int i = 0; i < currentretain.length; i++)
        {
            for (int j = 0; j < currentretain[i].length; j++)
            {
                for (int k = 0; k < currentretain[i][j].size(); k++)
                {
                    currentretainpart0.add(new deroctetstring(
                        (byte[])currentretain[i][j].elementat(k)));
                }
                currentretainpart1.add(new dersequence(currentretainpart0));
                currentretainpart0 = new asn1encodablevector();
            }
            currentretainpart2.add(new dersequence(currentretainpart1));
            currentretainpart1 = new asn1encodablevector();
        }
        result.add(new dersequence(currentretainpart2));

        // --- encode <nextretain>.
        asn1encodablevector nextretainpart0 = new asn1encodablevector();
        asn1encodablevector nextretainpart1 = new asn1encodablevector();
        asn1encodablevector nextretainpart2 = new asn1encodablevector();
        for (int i = 0; i < nextretain.length; i++)
        {
            for (int j = 0; j < nextretain[i].length; j++)
            {
                for (int k = 0; k < nextretain[i][j].size(); k++)
                {
                    nextretainpart0.add(new deroctetstring(
                        (byte[])nextretain[i][j].elementat(k)));
                }
                nextretainpart1.add(new dersequence(nextretainpart0));
                nextretainpart0 = new asn1encodablevector();
            }
            nextretainpart2.add(new dersequence(nextretainpart1));
            nextretainpart1 = new asn1encodablevector();
        }
        result.add(new dersequence(nextretainpart2));

        // --- encode <nextnextleaf>.
        asn1encodablevector seqofleaf = new asn1encodablevector();
        seqofstat = new asn1encodablevector();
        seqofbyte = new asn1encodablevector();
        seqofint = new asn1encodablevector();

        for (int i = 0; i < nextnextleaf.length; i++)
        {
            seqofstat.add(new dersequence(algorithms[0]));

            byte[][] tempbyte = nextnextleaf[i].getstatbyte();
            seqofbyte.add(new deroctetstring(tempbyte[0]));
            seqofbyte.add(new deroctetstring(tempbyte[1]));
            seqofbyte.add(new deroctetstring(tempbyte[2]));
            seqofbyte.add(new deroctetstring(tempbyte[3]));
            seqofstat.add(new dersequence(seqofbyte));
            seqofbyte = new asn1encodablevector();

            int[] tempint = nextnextleaf[i].getstatint();
            seqofint.add(new asn1integer(tempint[0]));
            seqofint.add(new asn1integer(tempint[1]));
            seqofint.add(new asn1integer(tempint[2]));
            seqofint.add(new asn1integer(tempint[3]));
            seqofstat.add(new dersequence(seqofint));
            seqofint = new asn1encodablevector();

            seqofleaf.add(new dersequence(seqofstat));
            seqofstat = new asn1encodablevector();
        }
        result.add(new dersequence(seqofleaf));

        // --- encode <upperleaf>.
        asn1encodablevector seqofupperleaf = new asn1encodablevector();
        seqofstat = new asn1encodablevector();
        seqofbyte = new asn1encodablevector();
        seqofint = new asn1encodablevector();

        for (int i = 0; i < upperleaf.length; i++)
        {
            seqofstat.add(new dersequence(algorithms[0]));

            byte[][] tempbyte = upperleaf[i].getstatbyte();
            seqofbyte.add(new deroctetstring(tempbyte[0]));
            seqofbyte.add(new deroctetstring(tempbyte[1]));
            seqofbyte.add(new deroctetstring(tempbyte[2]));
            seqofbyte.add(new deroctetstring(tempbyte[3]));
            seqofstat.add(new dersequence(seqofbyte));
            seqofbyte = new asn1encodablevector();

            int[] tempint = upperleaf[i].getstatint();
            seqofint.add(new asn1integer(tempint[0]));
            seqofint.add(new asn1integer(tempint[1]));
            seqofint.add(new asn1integer(tempint[2]));
            seqofint.add(new asn1integer(tempint[3]));
            seqofstat.add(new dersequence(seqofint));
            seqofint = new asn1encodablevector();

            seqofupperleaf.add(new dersequence(seqofstat));
            seqofstat = new asn1encodablevector();
        }
        result.add(new dersequence(seqofupperleaf));

        // encode <uppertreehashleaf>
        asn1encodablevector seqofuppertreehashleaf = new asn1encodablevector();
        seqofstat = new asn1encodablevector();
        seqofbyte = new asn1encodablevector();
        seqofint = new asn1encodablevector();

        for (int i = 0; i < uppertreehashleaf.length; i++)
        {
            seqofstat.add(new dersequence(algorithms[0]));

            byte[][] tempbyte = uppertreehashleaf[i].getstatbyte();
            seqofbyte.add(new deroctetstring(tempbyte[0]));
            seqofbyte.add(new deroctetstring(tempbyte[1]));
            seqofbyte.add(new deroctetstring(tempbyte[2]));
            seqofbyte.add(new deroctetstring(tempbyte[3]));
            seqofstat.add(new dersequence(seqofbyte));
            seqofbyte = new asn1encodablevector();

            int[] tempint = uppertreehashleaf[i].getstatint();
            seqofint.add(new asn1integer(tempint[0]));
            seqofint.add(new asn1integer(tempint[1]));
            seqofint.add(new asn1integer(tempint[2]));
            seqofint.add(new asn1integer(tempint[3]));
            seqofstat.add(new dersequence(seqofint));
            seqofint = new asn1encodablevector();

            seqofuppertreehashleaf.add(new dersequence(seqofstat));
            seqofstat = new asn1encodablevector();
        }
        result.add(new dersequence(seqofuppertreehashleaf));

        // --- encode <mintreehash>.
        asn1encodablevector mintreehashpart = new asn1encodablevector();
        for (int i = 0; i < mintreehash.length; i++)
        {
            mintreehashpart.add(new asn1integer(mintreehash[i]));
        }
        result.add(new dersequence(mintreehashpart));

        // --- encode <nextroot>.
        asn1encodablevector nextrootpart = new asn1encodablevector();
        for (int i = 0; i < nextroot.length; i++)
        {
            nextrootpart.add(new deroctetstring(nextroot[i]));
        }
        result.add(new dersequence(nextrootpart));

        // --- encode <nextnextroot>.
        asn1encodablevector seqofnextnextroot = new asn1encodablevector();
        asn1encodablevector seqofnnrstats = new asn1encodablevector();
        asn1encodablevector seqofnnrstrings = new asn1encodablevector();
        asn1encodablevector seqofnnrbytes = new asn1encodablevector();
        asn1encodablevector seqofnnrints = new asn1encodablevector();
        asn1encodablevector seqofnnrtreehash = new asn1encodablevector();
        asn1encodablevector seqofnnrretain = new asn1encodablevector();

        for (int i = 0; i < nextnextroot.length; i++)
        {
            seqofnnrstats.add(new dersequence(algorithms[0]));
            seqofnnrstrings = new asn1encodablevector();

            int heightoftree = nextnextroot[i].getstatint()[0];
            int taillength = nextnextroot[i].getstatint()[7];

            seqofnnrbytes.add(new deroctetstring(
                nextnextroot[i].getstatbyte()[0]));
            for (int j = 0; j < heightoftree; j++)
            {
                seqofnnrbytes.add(new deroctetstring(nextnextroot[i]
                    .getstatbyte()[1 + j]));
            }
            for (int j = 0; j < taillength; j++)
            {
                seqofnnrbytes.add(new deroctetstring(nextnextroot[i]
                    .getstatbyte()[1 + heightoftree + j]));
            }

            seqofnnrstats.add(new dersequence(seqofnnrbytes));
            seqofnnrbytes = new asn1encodablevector();

            seqofnnrints.add(new asn1integer(heightoftree));
            seqofnnrints.add(new asn1integer(nextnextroot[i].getstatint()[1]));
            seqofnnrints.add(new asn1integer(nextnextroot[i].getstatint()[2]));
            seqofnnrints.add(new asn1integer(nextnextroot[i].getstatint()[3]));
            seqofnnrints.add(new asn1integer(nextnextroot[i].getstatint()[4]));
            seqofnnrints.add(new asn1integer(nextnextroot[i].getstatint()[5]));
            seqofnnrints.add(new asn1integer(nextnextroot[i].getstatint()[6]));
            seqofnnrints.add(new asn1integer(taillength));
            for (int j = 0; j < heightoftree; j++)
            {
                seqofnnrints.add(new asn1integer(
                    nextnextroot[i].getstatint()[8 + j]));
            }
            for (int j = 0; j < taillength; j++)
            {
                seqofnnrints.add(new asn1integer(nextnextroot[i].getstatint()[8
                    + heightoftree + j]));
            }

            seqofnnrstats.add(new dersequence(seqofnnrints));
            seqofnnrints = new asn1encodablevector();

            // add treehash of nextnextroot object
            // ----------------------------
            seqofstat = new asn1encodablevector();
            seqofbyte = new asn1encodablevector();
            seqofint = new asn1encodablevector();

            if (nextnextroot[i].gettreehash() != null)
            {
                for (int j = 0; j < nextnextroot[i].gettreehash().length; j++)
                {
                    seqofstat.add(new dersequence(algorithms[0]));

                    taillength = nextnextroot[i].gettreehash()[j].getstatint()[1];

                    seqofbyte.add(new deroctetstring(nextnextroot[i]
                        .gettreehash()[j].getstatbyte()[0]));
                    seqofbyte.add(new deroctetstring(nextnextroot[i]
                        .gettreehash()[j].getstatbyte()[1]));
                    seqofbyte.add(new deroctetstring(nextnextroot[i]
                        .gettreehash()[j].getstatbyte()[2]));
                    for (int k = 0; k < taillength; k++)
                    {
                        seqofbyte.add(new deroctetstring(nextnextroot[i]
                            .gettreehash()[j].getstatbyte()[3 + k]));
                    }
                    seqofstat.add(new dersequence(seqofbyte));
                    seqofbyte = new asn1encodablevector();

                    seqofint.add(new asn1integer(
                        nextnextroot[i].gettreehash()[j].getstatint()[0]));
                    seqofint.add(new asn1integer(taillength));
                    seqofint.add(new asn1integer(
                        nextnextroot[i].gettreehash()[j].getstatint()[2]));
                    seqofint.add(new asn1integer(
                        nextnextroot[i].gettreehash()[j].getstatint()[3]));
                    seqofint.add(new asn1integer(
                        nextnextroot[i].gettreehash()[j].getstatint()[4]));
                    seqofint.add(new asn1integer(
                        nextnextroot[i].gettreehash()[j].getstatint()[5]));
                    for (int k = 0; k < taillength; k++)
                    {
                        seqofint.add(new asn1integer(nextnextroot[i]
                            .gettreehash()[j].getstatint()[6 + k]));
                    }
                    seqofstat.add(new dersequence(seqofint));
                    seqofint = new asn1encodablevector();

                    seqofnnrtreehash.add(new dersequence(seqofstat));
                    seqofstat = new asn1encodablevector();
                }
            }
            // ----------------------------
            seqofnnrstats.add(new dersequence(seqofnnrtreehash));
            seqofnnrtreehash = new asn1encodablevector();

            // encode retain of nextnextroot
            // ----------------------------
            // --- encode <curretain>.
            currentretainpart0 = new asn1encodablevector();
            if (nextnextroot[i].getretain() != null)
            {
                for (int j = 0; j < nextnextroot[i].getretain().length; j++)
                {
                    for (int k = 0; k < nextnextroot[i].getretain()[j].size(); k++)
                    {
                        currentretainpart0.add(new deroctetstring(
                            (byte[])nextnextroot[i].getretain()[j]
                                .elementat(k)));
                    }
                    seqofnnrretain.add(new dersequence(currentretainpart0));
                    currentretainpart0 = new asn1encodablevector();
                }
            }
            // ----------------------------
            seqofnnrstats.add(new dersequence(seqofnnrretain));
            seqofnnrretain = new asn1encodablevector();

            seqofnextnextroot.add(new dersequence(seqofnnrstats));
            seqofnnrstats = new asn1encodablevector();
        }
        result.add(new dersequence(seqofnextnextroot));

        // --- encode <currootsig>.
        asn1encodablevector currootsigpart = new asn1encodablevector();
        for (int i = 0; i < currentrootsig.length; i++)
        {
            currootsigpart.add(new deroctetstring(currentrootsig[i]));
        }
        result.add(new dersequence(currootsigpart));

        // --- encode <nextrootsig>.
        asn1encodablevector seqofnextrootsigs = new asn1encodablevector();
        asn1encodablevector seqofnrsstats = new asn1encodablevector();
        asn1encodablevector seqofnrsstrings = new asn1encodablevector();
        asn1encodablevector seqofnrsbytes = new asn1encodablevector();
        asn1encodablevector seqofnrsints = new asn1encodablevector();

        for (int i = 0; i < nextrootsig.length; i++)
        {
            seqofnrsstats.add(new dersequence(algorithms[0]));
            seqofnrsstrings = new asn1encodablevector();

            seqofnrsbytes.add(new deroctetstring(
                nextrootsig[i].getstatbyte()[0]));
            seqofnrsbytes.add(new deroctetstring(
                nextrootsig[i].getstatbyte()[1]));
            seqofnrsbytes.add(new deroctetstring(
                nextrootsig[i].getstatbyte()[2]));
            seqofnrsbytes.add(new deroctetstring(
                nextrootsig[i].getstatbyte()[3]));
            seqofnrsbytes.add(new deroctetstring(
                nextrootsig[i].getstatbyte()[4]));

            seqofnrsstats.add(new dersequence(seqofnrsbytes));
            seqofnrsbytes = new asn1encodablevector();

            seqofnrsints.add(new asn1integer(nextrootsig[i].getstatint()[0]));
            seqofnrsints.add(new asn1integer(nextrootsig[i].getstatint()[1]));
            seqofnrsints.add(new asn1integer(nextrootsig[i].getstatint()[2]));
            seqofnrsints.add(new asn1integer(nextrootsig[i].getstatint()[3]));
            seqofnrsints.add(new asn1integer(nextrootsig[i].getstatint()[4]));
            seqofnrsints.add(new asn1integer(nextrootsig[i].getstatint()[5]));
            seqofnrsints.add(new asn1integer(nextrootsig[i].getstatint()[6]));
            seqofnrsints.add(new asn1integer(nextrootsig[i].getstatint()[7]));
            seqofnrsints.add(new asn1integer(nextrootsig[i].getstatint()[8]));

            seqofnrsstats.add(new dersequence(seqofnrsints));
            seqofnrsints = new asn1encodablevector();

            seqofnextrootsigs.add(new dersequence(seqofnrsstats));
            seqofnrsstats = new asn1encodablevector();
        }
        result.add(new dersequence(seqofnextrootsigs));

        // --- encode <parameterset>.
        asn1encodablevector parsetpart0 = new asn1encodablevector();
        asn1encodablevector parsetpart1 = new asn1encodablevector();
        asn1encodablevector parsetpart2 = new asn1encodablevector();
        asn1encodablevector parsetpart3 = new asn1encodablevector();

        for (int i = 0; i < gmssparameterset.getheightoftrees().length; i++)
        {
            parsetpart1.add(new asn1integer(
                gmssparameterset.getheightoftrees()[i]));
            parsetpart2.add(new asn1integer(gmssparameterset
                .getwinternitzparameter()[i]));
            parsetpart3.add(new asn1integer(gmssparameterset.getk()[i]));
        }
        parsetpart0.add(new asn1integer(gmssparameterset.getnumoflayers()));
        parsetpart0.add(new dersequence(parsetpart1));
        parsetpart0.add(new dersequence(parsetpart2));
        parsetpart0.add(new dersequence(parsetpart3));
        result.add(new dersequence(parsetpart0));

        // --- encode <names>.
        asn1encodablevector namespart = new asn1encodablevector();

        for (int i = 0; i < algorithms.length; i++)
        {
            namespart.add(algorithms[i]);
        }

        result.add(new dersequence(namespart));
        return new dersequence(result);

    }

    private static int checkbigintegerinintrange(asn1encodable a)
    {
        biginteger b = ((asn1integer)a).getvalue();
        if ((b.compareto(biginteger.valueof(integer.max_value)) > 0) ||
            (b.compareto(biginteger.valueof(integer.min_value)) < 0))
        {
            throw new illegalargumentexception("biginteger not in range: " + b.tostring());
        }
        return b.intvalue();
    }


    public asn1primitive toasn1primitive()
    {
        return this.primitive;
    }
}
