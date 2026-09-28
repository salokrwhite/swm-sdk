# Third-party notices

The Java SDK resolves these dependencies through Maven:

- BouncyCastle `bcprov-jdk18on`, used under the MIT license.
- Jackson `jackson-databind`, used under the Apache License 2.0.
- JNA and `jna-platform`, used under the Apache License 2.0 or LGPL 2.1.

The corresponding license texts are included in the published JAR metadata or
are available from the upstream Maven artifacts. No third-party native library
is copied into the SDK JAR. JNA may unpack its own `jnidispatch` binary at
runtime to call Windows system APIs.
