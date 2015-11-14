package org.ripple.bouncycastle.jcajce;

import java.security.algorithmparametergenerator;
import java.security.algorithmparameters;
import java.security.keyfactory;
import java.security.keypairgenerator;
import java.security.messagedigest;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.signature;
import java.security.cert.certificateexception;
import java.security.cert.certificatefactory;

import javax.crypto.cipher;
import javax.crypto.keyagreement;
import javax.crypto.keygenerator;
import javax.crypto.mac;
import javax.crypto.nosuchpaddingexception;
import javax.crypto.secretkeyfactory;

public class namedjcajcehelper
    implements jcajcehelper
{
    protected final string providername;

    public namedjcajcehelper(string providername)
    {
        this.providername = providername;
    }

    public cipher createcipher(
        string algorithm)
        throws nosuchalgorithmexception, nosuchpaddingexception, nosuchproviderexception
    {
        return cipher.getinstance(algorithm, providername);
    }

    public mac createmac(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception
    {
        return mac.getinstance(algorithm, providername);
    }

    public keyagreement createkeyagreement(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception
    {
        return keyagreement.getinstance(algorithm, providername);
    }

    public algorithmparametergenerator createalgorithmparametergenerator(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception
    {
        return algorithmparametergenerator.getinstance(algorithm, providername);
    }

    public algorithmparameters createalgorithmparameters(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception
    {
        return algorithmparameters.getinstance(algorithm, providername);
    }

    public keygenerator createkeygenerator(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception
    {
        return keygenerator.getinstance(algorithm, providername);
    }

    public keyfactory createkeyfactory(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception
    {
        return keyfactory.getinstance(algorithm, providername);
    }

    public secretkeyfactory createsecretkeyfactory(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception
    {
        return secretkeyfactory.getinstance(algorithm, providername);
    }

    public keypairgenerator createkeypairgenerator(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception
    {
        return keypairgenerator.getinstance(algorithm, providername);
    }

    public messagedigest createdigest(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception
    {
        return messagedigest.getinstance(algorithm, providername);
    }

    public signature createsignature(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception
    {
        return signature.getinstance(algorithm, providername);
    }

    public certificatefactory createcertificatefactory(string algorithm)
        throws nosuchalgorithmexception, certificateexception, nosuchproviderexception
    {
        return certificatefactory.getinstance(algorithm, providername);
    }
}
