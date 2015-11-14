package org.ripple.bouncycastle;

/**
 * the bouncy castle license
 *
 * copyright (c) 2000-2012 the legion of the bouncy castle (http://www.bouncycastle.org)
 * <p>
 * permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "software"), to deal in the software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the software, and to permit persons to whom the software is furnished to do so,
 * subject to the following conditions:
 * <p>
 * the above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the software.
 * <p>
 * the software is provided "as is", without warranty of any kind, express or implied,
 * including but not limited to the warranties of merchantability, fitness for a particular
 * purpose and noninfringement. in no event shall the authors or copyright holders be
 * liable for any claim, damages or other liability, whether in an action of contract, tort or
 * otherwise, arising from, out of or in connection with the software or the use or other
 * dealings in the software.
 */
public class license
{
    public static string licensetext =
      "copyright (c) 2000-2012 the legion of the bouncy castle (http://www.bouncycastle.org) "
      + system.getproperty("line.separator")
      + system.getproperty("line.separator")
      + "permission is hereby granted, free of charge, to any person obtaining a copy of this software "
      + system.getproperty("line.separator")
      + "and associated documentation files (the \"software\"), to deal in the software without restriction, "
      + system.getproperty("line.separator")
      + "including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, "
      + system.getproperty("line.separator")
      + "and/or sell copies of the software, and to permit persons to whom the software is furnished to do so,"
      + system.getproperty("line.separator")
      + "subject to the following conditions:"
      + system.getproperty("line.separator")
      + system.getproperty("line.separator")
      + "the above copyright notice and this permission notice shall be included in all copies or substantial"
      + system.getproperty("line.separator")
      + "portions of the software."
      + system.getproperty("line.separator")
      + system.getproperty("line.separator")
      + "the software is provided \"as is\", without warranty of any kind, express or implied,"
      + system.getproperty("line.separator")
      + "including but not limited to the warranties of merchantability, fitness for a particular"
      + system.getproperty("line.separator")
      + "purpose and noninfringement. in no event shall the authors or copyright holders be"
      + system.getproperty("line.separator")
      + "liable for any claim, damages or other liability, whether in an action of contract, tort or"
      + system.getproperty("line.separator")
      + "otherwise, arising from, out of or in connection with the software or the use or other"
      + system.getproperty("line.separator")
      + "dealings in the software.";

    public static void main(
        string[]    args)
    {
        system.out.println(licensetext);
    }
}
