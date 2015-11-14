package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.security.keyfactory;
import java.security.privatekey;
import java.security.provider;
import java.security.publickey;
import java.security.interfaces.dsaparams;
import java.security.interfaces.dsaprivatekey;
import java.security.interfaces.dsapublickey;
import java.security.interfaces.rsaprivatecrtkey;
import java.security.interfaces.rsapublickey;
import java.security.spec.dsaprivatekeyspec;
import java.security.spec.dsapublickeyspec;
import java.security.spec.rsaprivatecrtkeyspec;
import java.security.spec.rsapublickeyspec;
import java.util.date;

import org.ripple.bouncycastle.bcpg.bcpgkey;
import org.ripple.bouncycastle.bcpg.dsapublicbcpgkey;
import org.ripple.bouncycastle.bcpg.dsasecretbcpgkey;
import org.ripple.bouncycastle.bcpg.elgamalpublicbcpgkey;
import org.ripple.bouncycastle.bcpg.elgamalsecretbcpgkey;
import org.ripple.bouncycastle.bcpg.publickeyalgorithmtags;
import org.ripple.bouncycastle.bcpg.publickeypacket;
import org.ripple.bouncycastle.bcpg.rsapublicbcpgkey;
import org.ripple.bouncycastle.bcpg.rsasecretbcpgkey;
import org.ripple.bouncycastle.jcajce.defaultjcajcehelper;
import org.ripple.bouncycastle.jcajce.namedjcajcehelper;
import org.ripple.bouncycastle.jcajce.providerjcajcehelper;
import org.ripple.bouncycastle.jce.interfaces.elgamalprivatekey;
import org.ripple.bouncycastle.jce.interfaces.elgamalpublickey;
import org.ripple.bouncycastle.jce.spec.elgamalparameterspec;
import org.ripple.bouncycastle.jce.spec.elgamalprivatekeyspec;
import org.ripple.bouncycastle.jce.spec.elgamalpublickeyspec;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpprivatekey;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.operator.keyfingerprintcalculator;

public class jcapgpkeyconverter
{
    private operatorhelper helper = new operatorhelper(new defaultjcajcehelper());
    private keyfingerprintcalculator fingerprintcalculator = new jcakeyfingerprintcalculator();

    public jcapgpkeyconverter setprovider(provider provider)
    {
        this.helper = new operatorhelper(new providerjcajcehelper(provider));

        return this;
    }

    public jcapgpkeyconverter setprovider(string providername)
    {
        this.helper = new operatorhelper(new namedjcajcehelper(providername));

        return this;
    }

    public publickey getpublickey(pgppublickey publickey)
        throws pgpexception
    {
        keyfactory fact;

        publickeypacket publicpk = publickey.getpublickeypacket();

        try
        {
            switch (publicpk.getalgorithm())
            {
            case publickeyalgorithmtags.rsa_encrypt:
            case publickeyalgorithmtags.rsa_general:
            case publickeyalgorithmtags.rsa_sign:
                rsapublicbcpgkey rsak = (rsapublicbcpgkey)publicpk.getkey();
                rsapublickeyspec rsaspec = new rsapublickeyspec(rsak.getmodulus(), rsak.getpublicexponent());

                fact = helper.createkeyfactory("rsa");

                return fact.generatepublic(rsaspec);
            case publickeyalgorithmtags.dsa:
                dsapublicbcpgkey dsak = (dsapublicbcpgkey)publicpk.getkey();
                dsapublickeyspec dsaspec = new dsapublickeyspec(dsak.gety(), dsak.getp(), dsak.getq(), dsak.getg());

                fact = helper.createkeyfactory("dsa");

                return fact.generatepublic(dsaspec);
            case publickeyalgorithmtags.elgamal_encrypt:
            case publickeyalgorithmtags.elgamal_general:
                elgamalpublicbcpgkey elk = (elgamalpublicbcpgkey)publicpk.getkey();
                elgamalpublickeyspec elspec = new elgamalpublickeyspec(elk.gety(), new elgamalparameterspec(elk.getp(), elk.getg()));

                fact = helper.createkeyfactory("elgamal");

                return fact.generatepublic(elspec);
            default:
                throw new pgpexception("unknown public key algorithm encountered");
            }
        }
        catch (pgpexception e)
        {
            throw e;
        }
        catch (exception e)
        {
            throw new pgpexception("exception constructing public key", e);
        }
    }

    /**
     * create a pgppublickey from the passed in jca one.
     * <p/>
     * note: the time passed in affects the value of the key's keyid, so you probably only want
     * to do this once for a jca key, or make sure you keep track of the time you used.
     *
     * @param algorithm asymmetric algorithm type representing the public key.
     * @param pubkey    actual public key to associate.
     * @param time      date of creation.
     * @throws pgpexception on key creation problem.
     */
    public pgppublickey getpgppublickey(int algorithm, publickey pubkey, date time)
        throws pgpexception
    {
        bcpgkey bcpgkey;

        if (pubkey instanceof rsapublickey)
        {
            rsapublickey rk = (rsapublickey)pubkey;

            bcpgkey = new rsapublicbcpgkey(rk.getmodulus(), rk.getpublicexponent());
        }
        else if (pubkey instanceof dsapublickey)
        {
            dsapublickey dk = (dsapublickey)pubkey;
            dsaparams dp = dk.getparams();

            bcpgkey = new dsapublicbcpgkey(dp.getp(), dp.getq(), dp.getg(), dk.gety());
        }
        else if (pubkey instanceof elgamalpublickey)
        {
            elgamalpublickey ek = (elgamalpublickey)pubkey;
            elgamalparameterspec es = ek.getparameters();

            bcpgkey = new elgamalpublicbcpgkey(es.getp(), es.getg(), ek.gety());
        }
        else
        {
            throw new pgpexception("unknown key class");
        }

        return new pgppublickey(new publickeypacket(algorithm, time, bcpgkey), fingerprintcalculator);
    }

    public privatekey getprivatekey(pgpprivatekey privkey)
        throws pgpexception
    {
        if (privkey instanceof jcapgpprivatekey)
        {
            return ((jcapgpprivatekey)privkey).getprivatekey();
        }

        publickeypacket pubpk = privkey.getpublickeypacket();
        bcpgkey privpk = privkey.getprivatekeydatapacket();

        try
        {
            keyfactory fact;

            switch (pubpk.getalgorithm())
            {
            case pgppublickey.rsa_encrypt:
            case pgppublickey.rsa_general:
            case pgppublickey.rsa_sign:
                rsapublicbcpgkey rsapub = (rsapublicbcpgkey)pubpk.getkey();
                rsasecretbcpgkey rsapriv = (rsasecretbcpgkey)privpk;
                rsaprivatecrtkeyspec rsaprivspec = new rsaprivatecrtkeyspec(
                    rsapriv.getmodulus(),
                    rsapub.getpublicexponent(),
                    rsapriv.getprivateexponent(),
                    rsapriv.getprimep(),
                    rsapriv.getprimeq(),
                    rsapriv.getprimeexponentp(),
                    rsapriv.getprimeexponentq(),
                    rsapriv.getcrtcoefficient());

                fact = helper.createkeyfactory("rsa");

                return fact.generateprivate(rsaprivspec);
            case pgppublickey.dsa:
                dsapublicbcpgkey dsapub = (dsapublicbcpgkey)pubpk.getkey();
                dsasecretbcpgkey dsapriv = (dsasecretbcpgkey)privpk;
                dsaprivatekeyspec dsaprivspec =
                    new dsaprivatekeyspec(dsapriv.getx(), dsapub.getp(), dsapub.getq(), dsapub.getg());

                fact = helper.createkeyfactory("dsa");

                return fact.generateprivate(dsaprivspec);
            case pgppublickey.elgamal_encrypt:
            case pgppublickey.elgamal_general:
                elgamalpublicbcpgkey elpub = (elgamalpublicbcpgkey)pubpk.getkey();
                elgamalsecretbcpgkey elpriv = (elgamalsecretbcpgkey)privpk;
                elgamalprivatekeyspec elspec = new elgamalprivatekeyspec(elpriv.getx(), new elgamalparameterspec(elpub.getp(), elpub.getg()));

                fact = helper.createkeyfactory("elgamal");

                return fact.generateprivate(elspec);
            default:
                throw new pgpexception("unknown public key algorithm encountered");
            }
        }
        catch (pgpexception e)
        {
            throw e;
        }
        catch (exception e)
        {
            throw new pgpexception("exception constructing key", e);
        }
    }

    /**
     * convert a privatekey into a pgpprivatekey.
     *
     * @param pub   the corresponding pgppublickey to privkey.
     * @param privkey  the private key for the key in pub.
     * @return a pgpprivatekey
     * @throws pgpexception
     */
    public pgpprivatekey getpgpprivatekey(pgppublickey pub, privatekey privkey)
        throws pgpexception
    {
        bcpgkey privpk;

        switch (pub.getalgorithm())
        {
        case pgppublickey.rsa_encrypt:
        case pgppublickey.rsa_sign:
        case pgppublickey.rsa_general:
            rsaprivatecrtkey rsk = (rsaprivatecrtkey)privkey;

            privpk = new rsasecretbcpgkey(rsk.getprivateexponent(), rsk.getprimep(), rsk.getprimeq());
            break;
        case pgppublickey.dsa:
            dsaprivatekey dsk = (dsaprivatekey)privkey;

            privpk = new dsasecretbcpgkey(dsk.getx());
            break;
        case pgppublickey.elgamal_encrypt:
        case pgppublickey.elgamal_general:
            elgamalprivatekey esk = (elgamalprivatekey)privkey;

            privpk = new elgamalsecretbcpgkey(esk.getx());
            break;
        default:
            throw new pgpexception("unknown key class");
        }

        return new pgpprivatekey(pub.getkeyid(), pub.getpublickeypacket(), privpk);
    }
}
