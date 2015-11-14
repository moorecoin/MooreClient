package org.ripple.bouncycastle.jce.spec;

import java.security.spec.algorithmparameterspec;

/**
 * named curve generation spec
 * <p>
 * if you are using jdk 1.5 you should be looking at ecgenparameterspec.
 */
public class ecnamedcurvegenparameterspec
    implements algorithmparameterspec
{
    private string  name;

    public ecnamedcurvegenparameterspec(
        string name)
    {
        this.name = name;
    }

    /**
     * return the name of the curve the ec domain parameters belong to.
     */
    public string getname()
    {
        return name;
    }
}
