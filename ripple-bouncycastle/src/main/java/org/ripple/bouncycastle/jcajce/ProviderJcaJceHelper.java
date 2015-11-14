package org.ripple.bouncycastle.jcajce;

import java.security.algorithmparametergenerator;
import java.security.algorithmparameters;
import java.security.keyfactory;
import java.security.keypairgenerator;
import java.security.messagedigest;
import java.security.nosuchalgorithmexception;
import java.security.provider;
import java.security.signature;
import java.security.cert.certificateexception;
import java.security.cert.certificatefactory;

import javax.crypto.cipher;
import javax.crypto.keyagreement;
import javax.crypto.keygenerator;
import javax.crypto.mac;
import javax.crypto.nosuchpaddingexception;
import javax.crypto.secretkeyfactory;

public class providerjcajcehelper
    implements jcajcehelper
{
    protected final provider provider;

    public providerjcajcehelper(provider provider)
    {
        this.provider = provider;
    }

    public cipher createcipher(
        string algorithm)
        throws nosuchalgorithmexception, nosuchpaddingexception
    {
        return cipher.getinstance(algorithm, provider);
    }

    public mac createmac(string algorithm)
        throws nosuchalgorithmexception
    {
        return mac.getinstance(algorithm, provider);
    }

    public keyagreement createkeyagreement(string algorithm)
        throws nosuchalgorithmexception
    {
        return keyagreement.getinstance(algorithm, provider);
    }

    public algorithmparametergenerator createalgorithmparametergenerator(string algorithm)
        throws nosuchalgorithmexception
    {
        return algorithmparametergenerator.getinstance(algorithm, provider);
    }

    public algorithmparameters createalgorithmparameters(string algorithm)
        throws nosuchalgorithmexception
    {
        return algorithmparameters.getinstance(algorithm, provider);
    }

    public keygenerator createkeygenerator(string algorithm)
        throws nosuchalgorithmexception
    {
        return keygenerator.getinstance(algorithm, provider);
    }

    public keyfactory createkeyfactory(string algorithm)
        throws nosuchalgorithmexception
    {
        return keyfactory.getinstance(algorithm, provider);
    }

    public secretkeyfactory createsecretkeyfactory(string algorithm)
        throws nosuchalgorithmexception
    {
        return secretkeyfactory.getinstance(algorithm, provider);
    }

    public keypairgenerator createkeypairgenerator(string algorithm)
        throws nosuchalgorithmexception
    {
        return keypairgenerator.getinstance(algorithm, provider);
    }

    public messagedigest createdigest(string algorithm)
        throws nosuchalgorithmexception
    {
        return messagedigest.getinstance(algorithm, provider);
    }

    public signature createsignature(string algorithm)
        throws nosuchalgorithmexception
    {
        return signature.getinstance(algorithm, provider);
    }

    public certificatefactory createcertificatefactory(string algorithm)
        throws nosuchalgorithmexception, certificateexception
    {
        return certificatefactory.getinstance(algorithm, provider);
    }
}
