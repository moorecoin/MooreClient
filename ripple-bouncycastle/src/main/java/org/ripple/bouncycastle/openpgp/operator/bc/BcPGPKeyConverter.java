package org.ripple.bouncycastle.openpgp.operator.bc;

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
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dsaparameters;
import org.ripple.bouncycastle.crypto.params.dsaprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.dsapublickeyparameters;
import org.ripple.bouncycastle.crypto.params.elgamalparameters;
import org.ripple.bouncycastle.crypto.params.elgamalprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.elgamalpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.crypto.params.rsaprivatecrtkeyparameters;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpprivatekey;
import org.ripple.bouncycastle.openpgp.pgppublickey;

public class bcpgpkeyconverter
{
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
    public pgppublickey getpgppublickey(int algorithm, asymmetrickeyparameter pubkey, date time)
        throws pgpexception
    {
        bcpgkey bcpgkey;

        if (pubkey instanceof rsakeyparameters)
        {
            rsakeyparameters rk = (rsakeyparameters)pubkey;

            bcpgkey = new rsapublicbcpgkey(rk.getmodulus(), rk.getexponent());
        }
        else if (pubkey instanceof dsapublickeyparameters)
        {
            dsapublickeyparameters dk = (dsapublickeyparameters)pubkey;
            dsaparameters dp = dk.getparameters();

            bcpgkey = new dsapublicbcpgkey(dp.getp(), dp.getq(), dp.getg(), dk.gety());
        }
        else if (pubkey instanceof elgamalpublickeyparameters)
        {
            elgamalpublickeyparameters ek = (elgamalpublickeyparameters)pubkey;
            elgamalparameters es = ek.getparameters();

            bcpgkey = new elgamalpublicbcpgkey(es.getp(), es.getg(), ek.gety());
        }
        else
        {
            throw new pgpexception("unknown key class");
        }

        return new pgppublickey(new publickeypacket(algorithm, time, bcpgkey), new bckeyfingerprintcalculator());
    }

    public pgpprivatekey getpgpprivatekey(pgppublickey pubkey, asymmetrickeyparameter privkey)
        throws pgpexception
    {
        bcpgkey privpk;

        switch (pubkey.getalgorithm())
        {
        case pgppublickey.rsa_encrypt:
        case pgppublickey.rsa_sign:
        case pgppublickey.rsa_general:
            rsaprivatecrtkeyparameters rsk = (rsaprivatecrtkeyparameters)privkey;

            privpk = new rsasecretbcpgkey(rsk.getexponent(), rsk.getp(), rsk.getq());
            break;
        case pgppublickey.dsa:
            dsaprivatekeyparameters dsk = (dsaprivatekeyparameters)privkey;

            privpk = new dsasecretbcpgkey(dsk.getx());
            break;
        case pgppublickey.elgamal_encrypt:
        case pgppublickey.elgamal_general:
            elgamalprivatekeyparameters esk = (elgamalprivatekeyparameters)privkey;

            privpk = new elgamalsecretbcpgkey(esk.getx());
            break;
        default:
            throw new pgpexception("unknown key class");
        }
        return new pgpprivatekey(pubkey.getkeyid(), pubkey.getpublickeypacket(), privpk);
    }

    public asymmetrickeyparameter getpublickey(pgppublickey publickey)
        throws pgpexception
    {
        publickeypacket publicpk = publickey.getpublickeypacket();

        try
        {
            switch (publicpk.getalgorithm())
            {
            case publickeyalgorithmtags.rsa_encrypt:
            case publickeyalgorithmtags.rsa_general:
            case publickeyalgorithmtags.rsa_sign:
                rsapublicbcpgkey rsak = (rsapublicbcpgkey)publicpk.getkey();

                return new rsakeyparameters(false, rsak.getmodulus(), rsak.getpublicexponent());
            case publickeyalgorithmtags.dsa:
                dsapublicbcpgkey dsak = (dsapublicbcpgkey)publicpk.getkey();

                return new dsapublickeyparameters(dsak.gety(), new dsaparameters(dsak.getp(), dsak.getq(), dsak.getg()));
            case publickeyalgorithmtags.elgamal_encrypt:
            case publickeyalgorithmtags.elgamal_general:
                elgamalpublicbcpgkey elk = (elgamalpublicbcpgkey)publicpk.getkey();

                return new elgamalpublickeyparameters(elk.gety(), new elgamalparameters(elk.getp(), elk.getg()));
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

    public asymmetrickeyparameter getprivatekey(pgpprivatekey privkey)
        throws pgpexception
    {
        publickeypacket pubpk = privkey.getpublickeypacket();
        bcpgkey privpk = privkey.getprivatekeydatapacket();

        try
        {
            switch (pubpk.getalgorithm())
            {
            case pgppublickey.rsa_encrypt:
            case pgppublickey.rsa_general:
            case pgppublickey.rsa_sign:
                rsapublicbcpgkey rsapub = (rsapublicbcpgkey)pubpk.getkey();
                rsasecretbcpgkey rsapriv = (rsasecretbcpgkey)privpk;

                return new rsaprivatecrtkeyparameters(rsapriv.getmodulus(), rsapub.getpublicexponent(), rsapriv.getprivateexponent(), rsapriv.getprimep(), rsapriv.getprimeq(), rsapriv.getprimeexponentp(), rsapriv.getprimeexponentq(), rsapriv.getcrtcoefficient());
            case pgppublickey.dsa:
                dsapublicbcpgkey dsapub = (dsapublicbcpgkey)pubpk.getkey();
                dsasecretbcpgkey dsapriv = (dsasecretbcpgkey)privpk;

                return new dsaprivatekeyparameters(dsapriv.getx(), new dsaparameters(dsapub.getp(), dsapub.getq(), dsapub.getg()));
            case pgppublickey.elgamal_encrypt:
            case pgppublickey.elgamal_general:
                elgamalpublicbcpgkey elpub = (elgamalpublicbcpgkey)pubpk.getkey();
                elgamalsecretbcpgkey elpriv = (elgamalsecretbcpgkey)privpk;

                return new elgamalprivatekeyparameters(elpriv.getx(), new elgamalparameters(elpub.getp(), elpub.getg()));
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
}
