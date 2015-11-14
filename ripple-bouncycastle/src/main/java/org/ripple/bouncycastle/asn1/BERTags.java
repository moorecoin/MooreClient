package org.ripple.bouncycastle.asn1;

public interface bertags
{
    public static final int boolean             = 0x01;
    public static final int integer             = 0x02;
    public static final int bit_string          = 0x03;
    public static final int octet_string        = 0x04;
    public static final int null                = 0x05;
    public static final int object_identifier   = 0x06;
    public static final int external            = 0x08;
    public static final int enumerated          = 0x0a;
    public static final int sequence            = 0x10;
    public static final int sequence_of         = 0x10; // for completeness
    public static final int set                 = 0x11;
    public static final int set_of              = 0x11; // for completeness


    public static final int numeric_string      = 0x12;
    public static final int printable_string    = 0x13;
    public static final int t61_string          = 0x14;
    public static final int videotex_string     = 0x15;
    public static final int ia5_string          = 0x16;
    public static final int utc_time            = 0x17;
    public static final int generalized_time    = 0x18;
    public static final int graphic_string      = 0x19;
    public static final int visible_string      = 0x1a;
    public static final int general_string      = 0x1b;
    public static final int universal_string    = 0x1c;
    public static final int bmp_string          = 0x1e;
    public static final int utf8_string         = 0x0c;
    
    public static final int constructed         = 0x20;
    public static final int application         = 0x40;
    public static final int tagged              = 0x80;
}
