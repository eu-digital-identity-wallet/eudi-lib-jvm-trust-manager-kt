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

package eu.europa.ec.eudi.trustmanager.internal

import COSE.Message
import COSE.MessageTag
import COSE.OneKey
import COSE.Sign1Message
import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import eu.europa.ec.eudi.trustmanager.*
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Date

internal class IssuerDataAuthenticationImpl(
    private var trustStore: TrustStore,
    private var currentDate: Date = Date()
) : Verifier<IssuerSignedData> {

    fun withCurrentDate(currentDate: Date): IssuerDataAuthenticationImpl {
        this.currentDate = currentDate
        return this
    }

    override suspend fun verify(data: IssuerSignedData): List<VerificationResult> {

        val results = mutableListOf<VerificationResult>()

        // parse IssuerAuthData and find x5chain
        val x5cChain = runCatching {
            parseX5c(data.issuerAuthData)
        }.getOrElse {
            results.add(
                if (it is VerificationException)
                    CertificatePathVerificationResult.Failure(it.error)
                else
                    CertificatePathVerificationResult.Failure(
                        MSOVerificationError.X5cValidationError(
                            "Error parsing x5chain"
                        )
                    )
            )
            return results
        }

        // check that IACA root certificate is not included in the chain
        if (!ensureIACAisNotIncluded(x5cChain)) {
            results.add(
                CertificatePathVerificationResult.Failure(
                    MSOVerificationError.X5cValidationError(
                        "IACA root certificate shall not be included in the x5chain"
                    )
                )
            )
            return results
        }

        // check MSO structure
        checkMSOStructure(data.issuerAuthData).let {
            results.add(it)
        }

        // check MSO signature
        validateMSOSignature(data.issuerAuthData, x5cChain.first().publicKey).let {
            results.add(it)
        }

        // check docType
        validateDocType(data.issuerAuthData, data.docType).let {
            results.add(it)
        }

        // check validity info
        checkValidityInfo(data.issuerAuthData, x5cChain.first()).let {
            results.add(it)
        }

        // check digest values
        data.issuerNameSpaces?.let {
            checkDigestValues(
                data.issuerNameSpaces,
                data.issuerAuthData
            ).let {
                results.add(it)
            }
        }

        // certificate path validation
        trustStore.validateCertificatePath(x5cChain).let {
            results.add(it)
        }

        return results
    }

    private fun parseX5c(issuerAuth: IssuerAuthData): List<X509Certificate> {

        val x5chain = validateSign1Message(
            (Message.DecodeFromBytes(
                issuerAuth,
                MessageTag.Sign1
            ) as Sign1Message)
        )

        when (x5chain.type) {
            CBORType.Array -> {
                return x5chain.values.map { item ->
                    when (item.type) {
                        CBORType.ByteString -> {
                            item.GetByteString().toX509Certificate()
                        }

                        else -> throw MSOVerificationError.X5cValidationError("Unexpected type for x5chain element")
                            .asException()
                    }
                }
            }

            CBORType.ByteString -> {
                return listOf(x5chain.GetByteString().toX509Certificate())
            }

            else -> throw MSOVerificationError.X5cValidationError("Unexpected type for x5chain element")
                .asException()
        }
    }

    private fun validateSign1Message(sign1Message: Sign1Message): CBORObject {
        // The alg element (RFC 8152), 1, shall be included as an element in the protected header.
        // Other elements should not be present in the protected header.
        ensure(
            sign1Message.protectedAttributes.ContainsKey(1) &&
                    sign1Message.protectedAttributes.keys.size == 1
        ) {
            MSOVerificationError.X5cValidationError("Only alg element should be present in the protected header")
                .asException()
        }

        // x5chain, 33, element should be present
        ensure(sign1Message.unprotectedAttributes.ContainsKey(33)) {
            MSOVerificationError.X5cValidationError("x5chain element not found").asException()
        }

        return sign1Message.unprotectedAttributes.get(33)
    }

    private fun validateMSOSignature(
        issuerAuth: IssuerAuthData,
        publicKey: PublicKey
    ): MSOVerificationResult.SignatureVerificationResult {
        try {
            (Message.DecodeFromBytes(issuerAuth, MessageTag.Sign1) as Sign1Message).validate(
                OneKey(
                    publicKey,
                    null
                )
            )
            return MSOVerificationResult.SignatureVerificationResult.Success
        } catch (e: Exception) {
            return MSOVerificationResult.SignatureVerificationResult.Failure(
                MSOVerificationError.SignatureValidationError(
                    "Signature verification failed: ${e.message}"
                )
            )
        }
    }

    private fun ensureIACAisNotIncluded(chain: List<X509Certificate>): Boolean {
        chain.forEach {
            if (it.issuerX500Principal.name == it.subjectX500Principal.name) {
                return false
            }
        }
        return true
    }

    private fun checkMSOStructure(issuerAuth: IssuerAuthData): MSOVerificationResult.MSOStructureVerificationResult {
        (Message.DecodeFromBytes(
            issuerAuth,
            MessageTag.Sign1
        ) as Sign1Message).let { sign1Message ->
            CBORObject.DecodeFromBytes(sign1Message.GetContent()).let { content ->
                val mso = CBORObject.DecodeFromBytes(content.GetByteString())
                val version = mso.get("version")
                ensure(
                    version != null &&
                            version.type == CBORType.TextString
                ) {
                    return MSOVerificationResult.MSOStructureVerificationResult.Failure(
                        MSOVerificationError.MSOStructureValidationError("Version shall not be empty")
                    )
                }
                val validDigestAlgorithms = listOf("SHA-256", "SHA-384", "SHA-512")
                val digestAlgorithm = mso.get("digestAlgorithm")
                ensure(
                    digestAlgorithm.type == CBORType.TextString
                            && validDigestAlgorithms.contains(digestAlgorithm.AsString())
                ) {
                    return MSOVerificationResult.MSOStructureVerificationResult.Failure(
                        MSOVerificationError.MSOStructureValidationError("digestAlgorithm should be SHA-256 or SHA-384 or SHA-512")
                    )
                }

                val valueDigests = mso.get("valueDigests")
                ensure(
                    valueDigests != null &&
                            valueDigests.type == CBORType.Map
                            && valueDigests.size() > 0
                ) {
                    return MSOVerificationResult.MSOStructureVerificationResult.Failure(
                        MSOVerificationError.MSOStructureValidationError("valueDigest shall be a non-empty map")
                    )
                }

                val deviceKeyInfo = mso.get("deviceKeyInfo")
                ensure(
                    deviceKeyInfo != null && deviceKeyInfo.type == CBORType.Map && deviceKeyInfo.ContainsKey(
                        "deviceKey"
                    )
                ) {
                    return MSOVerificationResult.MSOStructureVerificationResult.Failure(
                        MSOVerificationError.MSOStructureValidationError("deviceKeyInfo shall be a non-empty map that contains deviceKey")
                    )
                }
                val deviceKey = deviceKeyInfo.get("deviceKey")
                ensure(deviceKey != null && kotlin.runCatching { OneKey(deviceKey) }
                    .getOrNull() != null) {
                    return MSOVerificationResult.MSOStructureVerificationResult.Failure(
                        MSOVerificationError.MSOStructureValidationError("deviceKey shall not be empty and shall be a valid COSE key")
                    )
                }

                val docType = mso.get("docType").AsString()
                ensure(docType != null) {
                    return MSOVerificationResult.MSOStructureVerificationResult.Failure(
                        MSOVerificationError.MSOStructureValidationError("docType shall not be empty")
                    )
                }
                val validityInfo = mso.get("validityInfo")
                ensure(validityInfo != null && validityInfo.type == CBORType.Map) {
                    return MSOVerificationResult.MSOStructureVerificationResult.Failure(
                        MSOVerificationError.MSOStructureValidationError("validityInfo shall not be empty")
                    )
                }
                val signed = validityInfo.get("signed")
                ensure(signed != null) {
                    return MSOVerificationResult.MSOStructureVerificationResult.Failure(
                        MSOVerificationError.MSOStructureValidationError("signed in validityInfo shall not be empty")
                    )
                }
                val validFrom = validityInfo.get("validFrom")
                ensure(validFrom != null) {
                    return MSOVerificationResult.MSOStructureVerificationResult.Failure(
                        MSOVerificationError.MSOStructureValidationError("validFrom in validityInfo shall not be empty")
                    )
                }
                val validUntil = validityInfo.get("validUntil")
                ensure(validUntil != null) {
                    return MSOVerificationResult.MSOStructureVerificationResult.Failure(
                        MSOVerificationError.MSOStructureValidationError("validUntil in validityInfo shall not be empty")
                    )
                }
            }
        }
        return MSOVerificationResult.MSOStructureVerificationResult.Success
    }

    private fun validateDocType(
        issuerAuth: IssuerAuthData,
        docType: DocType
    ): MSOVerificationResult.DocTypeVerificationResult {
        (Message.DecodeFromBytes(
            issuerAuth,
            MessageTag.Sign1
        ) as Sign1Message).let { sign1Message ->
            CBORObject.DecodeFromBytes(sign1Message.GetContent()).let { content ->
                val msoDocType = CBORObject.DecodeFromBytes(content.GetByteString()).get("docType")
                if (msoDocType.AsString() != docType) {
                    return MSOVerificationResult.DocTypeVerificationResult.Failure(
                        MSOVerificationError.DocTypeNotMatch("DocType does not match")
                    )
                }
                return MSOVerificationResult.DocTypeVerificationResult.Success
            }
        }
    }

    private fun checkValidityInfo(
        issuerAuth: IssuerAuthData,
        dsCertificate: X509Certificate
    ): MSOVerificationResult.ValidityInfoVerificationResult {

        (Message.DecodeFromBytes(
            issuerAuth,
            MessageTag.Sign1
        ) as Sign1Message).let { sign1Message ->
            CBORObject.DecodeFromBytes(sign1Message.GetContent()).let { content ->
                val validityInfo =
                    CBORObject.DecodeFromBytes(content.GetByteString()).get("validityInfo")
                validityInfo.apply {

                    val signed = get("signed").AsString().toOffsetDateTime()
                    val validFrom = get("validFrom").AsString().toOffsetDateTime()
                    val validUntil = get("validUntil").AsString().toOffsetDateTime()
                    val currentTimestamp =
                        OffsetDateTime.ofInstant(currentDate.toInstant(), ZoneOffset.UTC)

                    if (!(validFrom.isEqual(signed) or validFrom.isAfter(signed))) {
                        return MSOVerificationResult.ValidityInfoVerificationResult.Failure(
                            MSOVerificationError.ValidityInfoValidationError("validFrom is not equal or after signed")
                        )
                    }

                    if (!(currentTimestamp.isEqual(validFrom) or currentTimestamp.isAfter(validFrom))) {
                        return MSOVerificationResult.ValidityInfoVerificationResult.Failure(
                            MSOVerificationError.ValidityInfoValidationError("current timestamp is not equal or later than validFrom")
                        )
                    }

                    if (!(validUntil.isAfter(validFrom))) {
                        return MSOVerificationResult.ValidityInfoVerificationResult.Failure(
                            MSOVerificationError.ValidityInfoValidationError("validUntil is not after validFrom")
                        )
                    }

                    if (!(validFrom.isEqual(currentTimestamp) or validUntil.isAfter(currentTimestamp))) {
                        return MSOVerificationResult.ValidityInfoVerificationResult.Failure(
                            MSOVerificationError.ValidityInfoValidationError("validUntil is not equal or after current timestamp")
                        )
                    }

                    val dsCertificateValidFrom =
                        dsCertificate.notBefore.toInstant().atOffset(ZoneOffset.UTC)
                    val dsCertificateValidUntil =
                        dsCertificate.notAfter.toInstant().atOffset(ZoneOffset.UTC)
                    if (!((signed.isEqual(dsCertificateValidFrom) or signed.isAfter(
                            dsCertificateValidFrom
                        )) &&
                                (signed.isEqual(dsCertificateValidUntil) or signed.isBefore(
                                    dsCertificateValidUntil
                                )))
                    ) {
                        return MSOVerificationResult.ValidityInfoVerificationResult.Failure(
                            MSOVerificationError.ValidityInfoValidationError("signed is not inside the validity period of DS certificate")
                        )
                    }
                }
            }
        }

        return MSOVerificationResult.ValidityInfoVerificationResult.Success
    }

    private fun checkDigestValues(
        issuerNameSpaces: IssuerNameSpaces,
        issuerAuth: IssuerAuthData
    ): MSOVerificationResult {
        val digestAlgorithm = issuerAuth.getDigestAlgorithm()
        val issuerNameSpacesCBORObject = CBORObject.DecodeFromBytes(issuerNameSpaces)
        ensure(issuerNameSpacesCBORObject.type == CBORType.Map) {
            MSOVerificationError.DigestValueValidationError("Unexpected type for issuerNameSpaces it should be a map")
                .asException()
        }
        issuerNameSpacesCBORObject.entries.forEach {
            val namespace = it.key.AsString()
            val issuerSignedItemBytesArray = it.value
            ensure(issuerSignedItemBytesArray.type == CBORType.Array) {
                MSOVerificationError.DigestValueValidationError("Unexpected type for issuerSignedItemBytes it should be an array")
                    .asException()
            }
            issuerSignedItemBytesArray.values.forEach { issuerSignedItem ->
                val issuerSignedItemBytes = issuerSignedItem.GetByteString()
                val digestID =
                    CBORObject.DecodeFromBytes(issuerSignedItemBytes).get("digestID").AsInt32()
                val hash = MessageDigest.getInstance(digestAlgorithm)
                    .digest(issuerSignedItemBytes)
                runCatching {
                    issuerAuth.getDigestValue(namespace, digestID).let { digestValue ->
                        if (!hash.contentEquals(digestValue)) {
                            return MSOVerificationResult.DigestValueVerificationResult.Failure(
                                MSOVerificationError.DigestValueValidationError("Hash mismatch")
                            )
                        }
                    }
                }.getOrElse { error ->
                    MSOVerificationResult.DigestValueVerificationResult.Failure(
                        MSOVerificationError.DigestValueValidationError(
                            error.message ?: "Digest value not found"
                        )
                    )
                }
            }
        }
        return MSOVerificationResult.DigestValueVerificationResult.Success
    }

    private fun ByteArray.toX509Certificate(): X509Certificate {
        return CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(this)
        ) as X509Certificate
    }

    private fun String.toOffsetDateTime(): OffsetDateTime {
        return OffsetDateTime.parse(this, DateTimeFormatter.ISO_DATE_TIME)
    }

    private fun IssuerAuthData.getDigestAlgorithm(): String {
        val sign1Message = Message.DecodeFromBytes(this, MessageTag.Sign1) as Sign1Message
        return CBORObject.DecodeFromBytes(sign1Message.GetContent()).let { content ->
            CBORObject.DecodeFromBytes(content.GetByteString()).get("digestAlgorithm").AsString()
        }
    }

    private fun IssuerAuthData.getDigestValue(namespace: String, digestID: Int): ByteArray {
        val sign1Message = Message.DecodeFromBytes(this, MessageTag.Sign1) as Sign1Message
        return CBORObject.DecodeFromBytes(sign1Message.GetContent()).let { content ->
            CBORObject.DecodeFromBytes(content.GetByteString()).get("digestValues")
                .let { digestValues ->
                    digestValues.get(namespace)?.let { namespaceMap ->
                        namespaceMap.get(digestID).GetByteString()
                            ?: throw MSOVerificationError.DigestValueValidationError("Digest value not found for DigestID $digestID")
                                .asException()
                    }
                        ?: throw MSOVerificationError.DigestValueValidationError("Namespace $namespace not found")
                            .asException()
                }
        }
    }
}