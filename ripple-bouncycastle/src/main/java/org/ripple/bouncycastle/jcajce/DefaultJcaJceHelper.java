package org.ripple.bouncycastle.jcajce;

import java.security.algorithmparametergenerator;
import java.security.algorithmparameters;
import java.security.keyfactory;
import java.security.keypairgenerator;
import java.security.messagedigest;
import java.security.nosuchalgorithmexception;
import java.security.signature;
import java.security.cert.certificateexception;
import java.security.cert.certificatefactory;

import javax.crypto.cipher;
import javax.crypto.keyagreement;
import javax.crypto.keygenerator;
import javax.crypto.mac;
import javax.crypto.nosuchpaddingexception;
import javax.crypto.secretkeyfactory;

public class defaultjcajcehelper
    implements jcajcehelper
{
    public cipher createcipher(
        string algorithm)
        throws nosuchalgorithmexception, nosuchpaddingexception
    {
        return cipher.getinstance(algorithm);
    }

    public mac createmac(string algorithm)
        throws nosuchalgorithmexception
    {
        return mac.getinstance(algorithm);
    }

    public keyagreement createkeyagreement(string algorithm)
        throws nosuchalgorithmexception
    {
        return keyagreement.getinstance(algorithm);
    }

    public algorithmparametergenerator createalgorithmparametergenerator(string algorithm)
        throws nosuchalgorithmexception
    {
        return algorithmparametergenerator.getinstance(algorithm);
    }

    public algorithmparameters createalgorithmparameters(string algorithm)
        throws nosuchalgorithmexception
    {
        return algorithmparameters.getinstance(algorithm);
    }

    public keygenerator createkeygenerator(string algorithm)
        throws nosuchalgorithmexception
    {
        return keygenerator.getinstance(algorithm);
    }

    public keyfactory createkeyfactory(string algorithm)
        throws nosuchalgorithmexception
    {
        return keyfactory.getinstance(algorithm);
    }

    public secretkeyfactory createsecretkeyfactory(string algorithm)
        throws nosuchalgorithmexception
    {
        return secretkeyfactory.getinstance(algorithm);
    }

    public keypairgenerator createkeypairgenerator(string algorithm)
        throws nosuchalgorithmexception
    {
        return keypairgenerator.getinstance(algorithm);
    }

    public messagedigest createdigest(string algorithm)
        throws nosuchalgorithmexception
    {
        return messagedigest.getinstance(algorithm);
    }

    public signature createsignature(string algorithm)
        throws nosuchalgorithmexception
    {
        return signature.getinstance(algorithm);
    }

    public certificatefactory createcertificatefactory(string algorithm)
        throws nosuchalgorithmexception, certificateexception
    {
        return certificatefactory.getinstance(algorithm);
    }
}
