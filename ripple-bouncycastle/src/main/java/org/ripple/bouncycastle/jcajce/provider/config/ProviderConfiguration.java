package org.ripple.bouncycastle.jcajce.provider.config;

import javax.crypto.spec.dhparameterspec;

import org.ripple.bouncycastle.jce.spec.ecparameterspec;

public interface providerconfiguration
{
    ecparameterspec getecimplicitlyca();

    dhparameterspec getdhdefaultparameters(int keysize);
}
