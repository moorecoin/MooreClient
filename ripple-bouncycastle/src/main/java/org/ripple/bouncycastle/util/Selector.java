package org.ripple.bouncycastle.util;

public interface selector
    extends cloneable
{
    boolean match(object obj);

    object clone();
}
