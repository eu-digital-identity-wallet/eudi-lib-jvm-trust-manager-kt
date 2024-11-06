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

import com.upokecenter.cbor.CBORObject
import eu.europa.ec.eudi.trustmanager.CertificatePathVerificationResult
import eu.europa.ec.eudi.trustmanager.IssuerSignedData
import eu.europa.ec.eudi.trustmanager.MSOVerificationResult
import kotlinx.coroutines.runBlocking
import org.bouncycastle.util.encoders.Hex
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import kotlin.test.Test
import kotlin.test.assertContains

class IssuerDataAuthenticationImplTest {

    @Test
    fun verifyIssuerAuth() = runBlocking {
        val sampleIACACertificate = CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(
                Base64.getDecoder().decode(
                    String(
                        ClassLoader.getSystemResourceAsStream("sample_iaca_pem")?.readAllBytes()!!
                    ).replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "")
                        .replace("\n", "")
                        .replace("\r", "")
                )
            )
        ) as X509Certificate

        val currentDate =
            Date(1622742217000) /*e.g. current date is Thursday, June 3, 2021 5:43:37 PM*/

        val trustStore = TrustStoreImpl(listOf(sampleIACACertificate))
            .withCurrentDate(currentDate)
            .withCRLValidationEnabled(false)

        val docType = "org.iso.18013.5.1.mDL"

        val result = IssuerDataAuthenticationImpl(trustStore)
            .withCurrentDate(currentDate)
            .verify(
                IssuerSignedData(
                    docType,
                    Hex.decode(
                        ClassLoader.getSystemResourceAsStream("sample_issuer_data_hex")
                            ?.readAllBytes()
                    )
                )
            )

        assert(result.size == 5)
        assertContains(result, CertificatePathVerificationResult.Success)
        assertContains(result, MSOVerificationResult.MSOStructureVerificationResult.Success)
        assertContains(result, MSOVerificationResult.DocTypeVerificationResult.Success)
        assertContains(result, MSOVerificationResult.SignatureVerificationResult.Success)
        assertContains(result, MSOVerificationResult.ValidityInfoVerificationResult.Success)
    }

    @Test
    fun verifyIssuerAuthAndNamespaces() = runBlocking {
        val sampleIACACertificate = CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(
                Base64.getDecoder().decode(
                    String(
                        ClassLoader.getSystemResourceAsStream("sample_iaca_pem")?.readAllBytes()!!
                    ).replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "")
                        .replace("\n", "")
                        .replace("\r", "")
                )
            )
        ) as X509Certificate

        val currentDate =
            Date(1622742217000) /*e.g. current date is Thursday, June 3, 2021 5:43:37 PM*/

        val trustStore = TrustStoreImpl(listOf(sampleIACACertificate))
            .withCurrentDate(currentDate)
            .withCRLValidationEnabled(false)

        val deviceResponse = Hex.decode(ClassLoader.getSystemResourceAsStream("sample_device_response_hex")?.readAllBytes())

        val issuerSignedData = CBORObject.DecodeFromBytes(deviceResponse).let {
            val document = it.get("documents")[0]
            val docType = document.get("docType").AsString()
            val issuerSigned = document.get("issuerSigned")
            val namespaces = issuerSigned.get("nameSpaces").EncodeToBytes()
            val issuerAuth = issuerSigned.get("issuerAuth").EncodeToBytes()
            IssuerSignedData(docType, issuerAuth, namespaces)
        }

        val result = IssuerDataAuthenticationImpl(trustStore)
            .withCurrentDate(currentDate)
            .verify(issuerSignedData)

        assert(result.size == 6)
        assertContains(result, CertificatePathVerificationResult.Success)
        assertContains(result, MSOVerificationResult.MSOStructureVerificationResult.Success)
        assertContains(result, MSOVerificationResult.DocTypeVerificationResult.Success)
        assertContains(result, MSOVerificationResult.SignatureVerificationResult.Success)
        assertContains(result, MSOVerificationResult.DigestValueVerificationResult.Success)
        assertContains(result, MSOVerificationResult.ValidityInfoVerificationResult.Success)
    }
}