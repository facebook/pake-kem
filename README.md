## pake-kem ![Build Status](https://github.com/facebook/pake-kem/workflows/CI/badge.svg)

An implementation of a password-authenticated key exchange (PAKE) based from a key encapsulation mechanism (KEM).

⚠️ **Warning**: This implementation has not been audited. Use at your own risk!

Documentation
-------------

The API can be found [here](https://docs.rs/pake-kem/) along with an example for usage.

Installation
------------

Add the following line to the dependencies of your `Cargo.toml`:

```
pake-kem = "0.1.0-pre.5"
```

Threat model
------------

This is NOT a post-quantum PAKE. This is a stopgap PAKE with a more complex set of security guarantees. It should only be used in scenarios that fit these guarantees. The first two are typical of any PAKE, the latter two are more particular to this one:

1. Passive adversaries cannot learn the session key produced by the PAKE. That is, if an attacker simply observes all messages sent in the protocol, they do not know what the final key is.
2. Active (i.e., man-in-the-middle) classical adversaries can make 1 password guess per PAKE execution. If they guess the password correctly, they learn the password and session key. 
3. Passive quantum adversaries can learn the password. That is, if a quantum adversary is given an execution transcript of the PAKE, they can launch a brute force attack on the password. Because of the structure of the transcript, they will know when their guess is correct. This doesn't reveal the session key, though (as guaranteed in point 1).
4. Active quantum adversaries can make an unbounded number of password guesses per PAKE session. If they can successfully brute-force the password in real time, they learn the password and session key.

### When to use this PAKE

A user should assume that a password used with this PAKE will eventually get revealed (via point 3). Further, they should assume that it is not a secure key exchange mechanism once quantum computers exist (via point 4).

This PAKE is appropriate if, for example, you are using one-time-use passwords, and you don't intend to keep this PAKE as a long-term solution.

Contributors
------------

The original author of this code is Kevin Lewi ([@kevinlewi](https://github.com/kevinlewi)).
To learn more about contributing to this project, [see this document](./CONTRIBUTING.md).

#### Acknowledgments

The author would like to thank Michael Rosenberg ([@rozbb](https://github.com/rozbb)) for the initial discussions
which helped lead to the creation of this library.

License
-------

This project is dual-licensed under either the [MIT license](https://github.com/facebook/pake-kem/blob/main/LICENSE-MIT)
or the [Apache License, Version 2.0](https://github.com/facebook/pake-kem/blob/main/LICENSE-APACHE).
You may select, at your option, one of the above-listed licenses.
