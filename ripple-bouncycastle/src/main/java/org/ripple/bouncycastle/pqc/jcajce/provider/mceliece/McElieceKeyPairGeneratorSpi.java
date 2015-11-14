package org.ripple.bouncycastle.pqc.jcajce.provider.mceliece;

import java.security.invalidalgorithmparameterexception;
import java.security.keypair;
import java.security.keypairgenerator;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliececca2keygenerationparameters;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliececca2keypairgenerator;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliececca2parameters;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliececca2privatekeyparameters;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliececca2publickeyparameters;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliecekeygenerationparameters;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliecekeypairgenerator;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mcelieceparameters;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mcelieceprivatekeyparameters;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliecepublickeyparameters;
import org.ripple.bouncycastle.pqc.jcajce.spec.ecckeygenparameterspec;
import org.ripple.bouncycastle.pqc.jcajce.spec.mceliececca2parameterspec;

public abstract class mceliecekeypairgeneratorspi
    extends keypairgenerator
{
    public mceliecekeypairgeneratorspi(
        string algorithmname)
    {
        super(algorithmname);
    }

    /**
     *
     *
     *
     */

    public static class mceliececca2
        extends mceliecekeypairgeneratorspi
    {

        mceliececca2keypairgenerator kpg;


        public mceliececca2()
        {
            super("mceliececca-2");
        }

        public mceliececca2(string s)
        {
            super(s);
        }

        public void initialize(algorithmparameterspec params)
            throws invalidalgorithmparameterexception
        {
            kpg = new mceliececca2keypairgenerator();
            super.initialize(params);
            ecckeygenparameterspec ecc = (ecckeygenparameterspec)params;

            mceliececca2keygenerationparameters mccca2kgparams = new mceliececca2keygenerationparameters(new securerandom(), new mceliececca2parameters(ecc.getm(), ecc.gett()));
            kpg.init(mccca2kgparams);
        }

        public void initialize(int keysize, securerandom random)
        {
            mceliececca2parameterspec paramspec = new mceliececca2parameterspec();

            // call the initializer with the chosen parameters
            try
            {
                this.initialize(paramspec);
            }
            catch (invalidalgorithmparameterexception ae)
            {
            }
        }

        public keypair generatekeypair()
        {
            asymmetriccipherkeypair generatekeypair = kpg.generatekeypair();
            mceliececca2privatekeyparameters sk = (mceliececca2privatekeyparameters)generatekeypair.getprivate();
            mceliececca2publickeyparameters pk = (mceliececca2publickeyparameters)generatekeypair.getpublic();

            return new keypair(new bcmceliececca2publickey(pk), new bcmceliececca2privatekey(sk));

        }

    }

    /**
     *
     *
     *
     */

    public static class mceliece
        extends mceliecekeypairgeneratorspi
    {

        mceliecekeypairgenerator kpg;


        public mceliece()
        {
            super("mceliece");
        }

        public void initialize(algorithmparameterspec params)
            throws invalidalgorithmparameterexception
        {
            kpg = new mceliecekeypairgenerator();
            super.initialize(params);
            ecckeygenparameterspec ecc = (ecckeygenparameterspec)params;

            mceliecekeygenerationparameters mcckgparams = new mceliecekeygenerationparameters(new securerandom(), new mcelieceparameters(ecc.getm(), ecc.gett()));
            kpg.init(mcckgparams);
        }

        public void initialize(int keysize, securerandom random)
        {
            ecckeygenparameterspec paramspec = new ecckeygenparameterspec();

            // call the initializer with the chosen parameters
            try
            {
                this.initialize(paramspec);
            }
            catch (invalidalgorithmparameterexception ae)
            {
            }
        }

        public keypair generatekeypair()
        {
            asymmetriccipherkeypair generatekeypair = kpg.generatekeypair();
            mcelieceprivatekeyparameters sk = (mcelieceprivatekeyparameters)generatekeypair.getprivate();
            mceliecepublickeyparameters pk = (mceliecepublickeyparameters)generatekeypair.getpublic();

            return new keypair(new bcmceliecepublickey(pk), new bcmcelieceprivatekey(sk));
        }

    }

}
