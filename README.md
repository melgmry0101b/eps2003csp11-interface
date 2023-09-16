eps2003csp11-interface
======================

A lightweight library that interfaces PKCS#11 libraries, with the added functionality of supporting CAdES-BES signing natively.

The library was originally built for `eps2003csp11.dll`, hence the name, but the functionality has been expanded adding the ability
to dynamically load different PKCS#11 modules.

What is this All About?
-----------------------

Recently we were working on integrating the new eTax system in Egypt. Part of the system includes signing the issued invoices with `CAdES-BES`. The certificates used for signing were provided on a `FEITIAN ePass2003 PKI Authentication Token`. The token uses a software provided by `EnterSafe` that exposes a `PKCS#11` interface through `eps2003csp11.dll`. We relied on solutions that used [BouncyCastle](https://www.bouncycastle.org/), most prominently what our colleague developed at [bassemAgmi/EInvoicingSigner](https://github.com/bassemAgmi/EInvoicingSigner). As I worked for a period on applications that issues invoices on Microsoft Access, interoperability and lesser overhead requirements arose which pushed for more versatile solutions. This is where we needed a native interface that is interoperable without much overhead.

This library provides the functionality needed to open the PKI token, and sign with CAdES-BES natively without the overhead of BouncyCastle for example.

**Recently, with version 2.0.0, the library has been expanded to be able to dynamically load different PKCS#11 modules
dynamically**.

What are the Limitations of this Library?
----------------------------------------

This library is developed natively for Windows platforms which renders it non-portable to other platforms as Macs or Linux. The library is developed to interact with the first token available to the system without the ability to select specific token. These limitations are mitigable, but needs some work, feel free to open an [issue](https://github.com/melgmry0101b/eps2003csp11-interface/issues/new) if you reached these limitations, or help us by opening a [pull request](https://github.com/melgmry0101b/eps2003csp11-interface/compare).

How to Use?
-----------

If you are linking this library to a project that takes header files, add [eps2003cspif.h](src/eps2003cspif/eps2003cspif.h) and [errcodes.h](src/eps2003cspif/errcodes.h) to your includes.

### Functions

```CPP
DLLENTRY(HRESULT) OpenKiLibrary(BSTR pwszLibName, BSTR pwszPin)
```

Opens the first token available to the system with the provided PIN, and using the provided PKCS#11 module.

```CPP
DLLENTRY(HRESULT) SignWithCadesBes(BSTR pwszRootCert, BSTR pwszData, BSTR *ppwszSignature)
```

Signs data in `pwszData` with the first certificate that is issued by `pwszRootCert`, and returns the signed data as `BSTR` in `ppwszSignature` **in base64**. This function uses `BSTR` that is allocated using `SysAllocString` and freed by `SysFreeString`. `BSTR`helps with interoperability with COM languages, e.g. VBA.

**NOTE:** You can use this function without a token if you have a certificate with its private key registered on the system.

```CPP
DLLENTRY(HRESULT) CloseKiLibrary()
```

Closes the previously opened token.

```CPP
DLLENTRY(HRESULT) SHA256(BYTE *pbData, DWORD cbData, BYTE **ppbHash, DWORD *pcbHash)
```

A helper function that natively creates SHA256.

```CPP
DLLENTRY(HRESULT) SHA256_STR(BYTE *pbData, DWORD cbData, BSTR *ppwszHash)
```

A helper function that creates SHA256 and provides the hash as hex string.

```CPP
DLLENTRY(HRESULT) BASE64(BYTE *pbData, DWORD cbData, BSTR *ppwszBase64)
```

A helper functions that creates Base64 natively.

Demo
----

Refer to [eps2003cspif-demo.cpp](demo/eps2003cspif-demo/eps2003cspif-demo.cpp) for a demo on using `SignWithCadesBes`.

Building and Running
--------------------

The library requires `Platform Toolset v143` which is shipped with `Visual Studio 2022` for building the source.

**Using the library on target machines requires [Visual C++ Redistributable 2022](https://learn.microsoft.com/en-US/cpp/windows/latest-supported-vc-redist?view=msvc-170#visual-studio-2015-2017-2019-and-2022).**

Footnotes
---------

The code in [ESSSigningCertificateV2](src/ESSSigningCertificateV2) is auto generated using [asn1c](https://github.com/vlm/asn1c). The ASN.1 file that is used for generation is in [ESSSigningCertificateV2.asn1](docs/asn1/ESSSigningCertificateV2.asn1).

References
----------

* [bassemAgmi/EInvoicingSigner](https://github.com/bassemAgmi/EInvoicingSigner)
* [The *AdES Collection: CAdES, XAdES, PAdES and ASiC Implementation for Windows in C++](https://www.codeproject.com/Articles/1256991/The-AdES-Collection-CAdES-XAdES-PAdES-and-ASiC)

Contributing
------------

We really appreciate any contribution, refere to [CONTRIBUTING.md](CONTRIBUTING.md).

License
-------

Licensed under [MIT](LICENSE).
