// eps2003cspif-demo.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <eps2003cspif.h>

int main()
{
    // As the library doesn't require an ePass2003 PKI for create CAdES-BES signature,
    //  that means you can use the provided method to sign with any other present
    //  certificate on the system.
    // NOTE: the library is linked against eps2003csp11.dll, thus it has to be present
    //  on your system.

    // The library uses BSTR for interoperability with languages that use COM,
    //  but you can pass WCHAR*, as the library doesn't use .

    HRESULT hr{ S_OK };

    BSTR pwszOutput{ nullptr };

    // The issuer of the certificate you are using for signing.
    // NOTE: You should have the private key of the certificate registered on your system.
    BSTR pwszCertificateIssue = SysAllocString(L"<YouCertificateNameGoesHere>");

    // The library currently signs text, although nothing prevents the base logic from
    //  signing any blobs, but, this is for another feature consideration :)
    BSTR pwszData = SysAllocString(L"Data to be signed.");

    // Now, sign!
    hr = SignWithCadesBes(pwszCertificateIssue, pwszData, &pwszOutput);
    if (SUCCEEDED(hr))
    {
        std::wcout << pwszOutput << std::endl;
    }
    else
    {
        std::printf("Error occurred during signing. HRESULT 0x%x\n", hr);
    }

    SysFreeString(pwszCertificateIssue);
    SysFreeString(pwszData);
    if (pwszOutput) { SysFreeString(pwszOutput); }

    return SUCCEEDED(hr) ? 0 : -1;
}
