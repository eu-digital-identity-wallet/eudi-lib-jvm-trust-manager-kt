/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package eu.europa.ec.eudi.trustmanager

import java.security.cert.X509Certificate

interface Verifier<T> {
    suspend fun verify(data: T): List<VerificationResult>
}

interface CRLValidator {
    suspend fun validateCRL(targetCertificate: X509Certificate, iacaCertificate: X509Certificate): CRLValidationResult
}

interface TrustStore {
    val trustedRoots: List<X509Certificate>
    suspend fun validateCertificatePath(chain: List<X509Certificate>): CertificatePathVerificationResult
}

typealias IssuerAuthData = ByteArray
typealias IssuerNameSpaces = ByteArray
typealias DocType = String

/**
 * The issuer signed data that contains the issuer auth data, the issuer name spaces and the docType
 * @property docType the ISO 18013-5 docType
 * @property issuerAuthData the issuer auth data (MSO)
 * @property issuerNameSpaces the issuer name spaces
 */
data class IssuerSignedData(
    val docType: DocType,
    val issuerAuthData: IssuerAuthData,
    val issuerNameSpaces: IssuerNameSpaces? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as IssuerSignedData

        if (docType != other.docType) return false
        if (!issuerAuthData.contentEquals(other.issuerAuthData)) return false
        if (issuerNameSpaces != null) {
            if (other.issuerNameSpaces == null) return false
            if (!issuerNameSpaces.contentEquals(other.issuerNameSpaces)) return false
        } else if (other.issuerNameSpaces != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = docType.hashCode()
        result = 31 * result + issuerAuthData.contentHashCode()
        result = 31 * result + (issuerNameSpaces?.contentHashCode() ?: 0)
        return result
    }
}

sealed interface VerificationResult

sealed interface CertificatePathVerificationResult : VerificationResult {
    data object Success : CertificatePathVerificationResult
    data class Failure(val error: VerificationError) : CertificatePathVerificationResult
}

sealed interface CRLValidationResult : VerificationResult {
    data object Success : CRLValidationResult
    data class Failure(val error: CertificateVerificationError.CRLValidationError) :
        CRLValidationResult
}

interface MSOVerificationResult : VerificationResult {

    sealed interface MSOStructureVerificationResult : MSOVerificationResult {
        data object Success : MSOStructureVerificationResult
        data class Failure(val error: MSOVerificationError) : MSOStructureVerificationResult
    }

    sealed interface SignatureVerificationResult : MSOVerificationResult {
        data object Success : SignatureVerificationResult
        data class Failure(val error: MSOVerificationError) : SignatureVerificationResult
    }

    sealed interface DocTypeVerificationResult : MSOVerificationResult {
        data object Success : DocTypeVerificationResult
        data class Failure(val error: MSOVerificationError) : DocTypeVerificationResult
    }

    sealed interface ValidityInfoVerificationResult : MSOVerificationResult {
        data object Success : ValidityInfoVerificationResult
        data class Failure(val error: MSOVerificationError) : ValidityInfoVerificationResult
    }

    sealed interface DigestValueVerificationResult : MSOVerificationResult {
        data object Success : DigestValueVerificationResult
        data class Failure(val error: MSOVerificationError) : DigestValueVerificationResult
    }
}

interface VerificationError

sealed interface CertificateVerificationError : VerificationError {
    data class CertificatePathVerificationError(val message: String) : CertificateVerificationError
    data class CRLValidationError(val message: String) : CertificateVerificationError
}

sealed interface MSOVerificationError : VerificationError {
    data class MSOStructureValidationError(val message: String) : MSOVerificationError
    data class X5cValidationError(val message: String) : MSOVerificationError
    data class SignatureValidationError(val message: String) : MSOVerificationError
    data class DocTypeNotMatch(val message: String) : MSOVerificationError
    data class ValidityInfoValidationError(val message: String) : MSOVerificationError
    data class DigestValueValidationError(val message: String) : MSOVerificationError
}