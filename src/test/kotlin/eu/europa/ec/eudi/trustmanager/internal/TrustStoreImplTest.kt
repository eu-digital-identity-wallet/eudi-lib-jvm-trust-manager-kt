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

import eu.europa.ec.eudi.trustmanager.CertificatePathVerificationResult
import kotlinx.coroutines.runBlocking
import org.bouncycastle.util.encoders.Hex

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import kotlin.test.Test

class TrustStoreImplTest {

    @Test
    fun testHappyScenario() = runBlocking {

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

        val dsCertificate = CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(
                Hex.decode(
                    String(
                        ClassLoader.getSystemResourceAsStream("sample_ds_hex")?.readAllBytes()!!
                    )
                )
            )
        ) as X509Certificate

        val currentDate = Date(1622742217000) /*e.g. current date is Thursday, June 3, 2021 5:43:37 PM*/

        val trustStore = TrustStoreImpl(listOf(sampleIACACertificate))
            .withCurrentDate(currentDate)
            .withCRLValidationEnabled(false)

        val result = trustStore.validateCertificatePath(listOf(dsCertificate))

        assert(result is CertificatePathVerificationResult.Success)
    }

    @Test
    fun testUnhappy() = runBlocking {

        val eudiIACACertificate = CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(
                Base64.getDecoder().decode(
                    String(
                        ClassLoader.getSystemResourceAsStream("eudi_iaca_pem")?.readAllBytes()!!
                    ).replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "")
                        .replace("\n", "")
                        .replace("\r", "")
                )
            )
        ) as X509Certificate

        val dsCertificate = CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(
                Hex.decode(
                    String(
                        ClassLoader.getSystemResourceAsStream("sample_ds_hex")?.readAllBytes()!!
                    )
                )
            )
        ) as X509Certificate

        val currentDate = Date(1622742217000) /*e.g. current date is Thursday, June 3, 2021 5:43:37 PM*/

        val trustStore = TrustStoreImpl(listOf(eudiIACACertificate))
            .withCurrentDate(currentDate)
            .withCRLValidationEnabled(false)

        val result = trustStore.validateCertificatePath(listOf(dsCertificate))

        assert(result is CertificatePathVerificationResult.Failure)
    }
}