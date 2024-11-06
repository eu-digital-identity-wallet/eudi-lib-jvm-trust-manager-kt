# EUDI Trust Manager library

:heavy_exclamation_mark: **Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## Table of contents
* [Overview](#overview)
* [Disclaimer](#disclaimer)
* [How to use](#how-to-use)
* [How to contribute](#how-to-contribute)
* [License](#license)

## Overview

This is a Kotlin library, targeting JVM, that performs the following validations according to the ISO/IEC 18013-5:

- [x] Certificate path validation of the certificate included in the MSO header,
- [x] Digital signature verification of the IssuerAuth structure,
- [x] Digest values validation,
- [x] DocType in the MSO matches the relevant DocType,
- [x] ValidityInfo structure validation.

## Disclaimer
The released software is an initial development release version:
-  The initial development release is an early endeavor reflecting the efforts of a short time-boxed period, and by no means can be considered as the final product.
-  The initial development release may be changed substantially over time, might introduce new features but also may change or remove existing ones, potentially breaking compatibility with your existing code.
-  The initial development release is limited in functional scope.
-  The initial development release may contain errors or design flaws and other problems that could cause system or other failures and data loss.
-  The initial development release has reduced security, privacy, availability, and reliability standards relative to future releases. This could make the software slower, less reliable, or more vulnerable to attacks than mature software.
-  The initial development release is not yet comprehensively documented.
-  Users of the software must perform sufficient engineering and additional testing to properly evaluate their application and determine whether any of the open-sourced components is suitable for use in that application.
-  We strongly recommend not putting this version of the software into production use.
-  Only the latest version of the software will be supported

## How to use
Include the library into your project:

```kotlin
// Include library in dependencies in build.gradle.kts
dependencies {
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-trust-manager-kt:$version")
}
```

### Instantiating the TrustManager
The library provides a `TrustManager` class that allows you to perform the validations mentioned above. 
The `TrustManager` class requires a list of trusted IACA certificates to be instantiated.

```kotlin
val trustedIACACertificates = listOf(IACACertificate1, IACACertificate2, /*...*/)
val trustManager = TrustManager { 
    withTrustStore(trustedIACACertificates) 
}
```

### Issuer signed data
In order to verify the IssuerSignedData, you need to call the `verify` method of the `TrustManager` class.
```kotlin
val issuerSignedData = IssuerSignedData(docType, issuerAuth, namespaces)
val result = trustManager.verify(issuerSignedData)
```
As a result, you will get a list of `ValidationResult` objects. Each `ValidationResult` object contains the validation result of a specific validation:
- `MSOVerificationResult.MSOStructureVerificationResult` - the result of the MSO structure verification,
- `MSOVerificationResult.DocTypeVerificationResult` - the result of the DocType verification,
- `MSOVerificationResult.SignatureVerificationResult` - the result of the signature verification,
- `MSOVerificationResult.DigestValueVerificationResult` - the result of the digest values verification,
- `MSOVerificationResult.ValidityInfoVerificationResult` - the result of the ValidityInfo structure verification.
- `CertificatePathVerificationResult` - the result of the ValidityInfo structure verification.


### Certificate path validation
In order to validate the certificate path, you need to call the `validateCertificatePath` method of the `TrustManager` class.
```kotlin
val certificateChain = listOf(certificate1, certificate2, /*...*/)
val result = trustManager.validateCertificatePath(certificateChain)
```

The result of the validation is a `CertificatePathVerificationResult` object that contains the validation result of the certificate path validation.

### CRL
In order to verify if a certificate is revoked or not by using the CRL, you need to call the `validateCRL` method of the `TrustManager` class.
```kotlin
val result = trustManager.validateCRL(targetCertificate, iacaCertificate)
```
The result of the validation is a `CRLVerificationResult` object that contains the validation result of the CRL validation.

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

### Third-party component licenses

* [CBOR-JAVA](https://github.com/peteroupc/CBOR-Java/)
* [COSE-JAVA](https://github.com/cose-wg/COSE-JAVA)
* [Bouncy Castle](https://www.bouncycastle.org)

### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
