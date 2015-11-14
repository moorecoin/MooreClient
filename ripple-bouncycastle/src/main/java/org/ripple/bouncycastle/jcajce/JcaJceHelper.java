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

public interface jcajcehelper
{
    cipher createcipher(
        string algorithm)
        throws nosuchalgorithmexception, nosuchpaddingexception, nosuchproviderexception;

    mac createmac(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception;

    keyagreement createkeyagreement(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception;

    algorithmparametergenerator createalgorithmparametergenerator(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception;

    algorithmparameters createalgorithmparameters(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception;

    keygenerator createkeygenerator(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception;

    keyfactory createkeyfactory(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception;

    secretkeyfactory createsecretkeyfactory(string algorithm)
           throws nosuchalgorithmexception, nosuchproviderexception;

    keypairgenerator createkeypairgenerator(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception;

    messagedigest createdigest(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception;

    signature createsignature(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception;

    certificatefactory createcertificatefactory(string algorithm)
        throws nosuchalgorithmexception, nosuchproviderexception, certificateexception;
}
