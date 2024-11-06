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

import eu.europa.ec.eudi.trustmanager.CRLValidationResult
import eu.europa.ec.eudi.trustmanager.CRLValidator
import eu.europa.ec.eudi.trustmanager.CertificateVerificationError
import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.net.URI
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.util.*

internal class CRLValidatorImpl(
    private var currentDate: Date = Date()
) : CRLValidator {

    fun withCurrentDate(currentDate: Date): CRLValidatorImpl {
        this.currentDate = currentDate
        return this
    }

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    override suspend fun validateCRL(
        targetCertificate: X509Certificate,
        iacaCertificate: X509Certificate
    ): CRLValidationResult {
        val crlDistributionPoints = getCRLDistributionPoints(iacaCertificate)
        if (crlDistributionPoints.isEmpty()) {
            return CRLValidationResult.Failure(CertificateVerificationError.CRLValidationError("No CRL distribution points found"))
        }
        crlDistributionPoints.forEach { crlUrl ->
            try {
                val crl = downloadCRLFromURL(crlUrl)

                // verify that the CRL is not expired
                if (currentDate.before(crl.thisUpdate) || (crl.nextUpdate != null && currentDate.after(
                        crl.nextUpdate
                    ))
                ) {
                    return CRLValidationResult.Failure(
                        CertificateVerificationError.CRLValidationError(
                            "CRL is expired or not yet valid"
                        )
                    )
                }

                // verify that the CRL and the target certificate are issued by the same IACA
                if (targetCertificate.issuerX500Principal != crl.issuerX500Principal) {
                    return CRLValidationResult.Failure(
                        CertificateVerificationError.CRLValidationError(
                            "CRL are not issued by the same IACA as the target certificate"
                        )
                    )
                }

                // verify CRL signature
                crl.verify(iacaCertificate.publicKey)

                // verify that the target certificate is not revoked
                if (crl.isRevoked(targetCertificate)) {
                    return CRLValidationResult.Failure(
                        CertificateVerificationError.CRLValidationError(
                            "Target certificate is revoked"
                        )
                    )
                }

            } catch (e: Exception) {
                return CRLValidationResult.Failure(CertificateVerificationError.CRLValidationError("Failed due to exception: ${e.message}"))
            }
        }
        return CRLValidationResult.Success
    }

    private fun downloadCRLFromURL(crlUrl: String): X509CRL {
        return URI.create(crlUrl)
            .toURL()
            .openStream()
            .use { inputStream ->
                CertificateFactory
                    .getInstance("X.509")
                    .generateCRL(inputStream) as X509CRL
            }
    }

    private fun getCRLDistributionPoints(certificate: X509Certificate): List<String> {
        val crlDistPointExt = certificate.getExtensionValue(Extension.cRLDistributionPoints.id)
        val distPoint = CRLDistPoint.getInstance(DEROctetString.getInstance(crlDistPointExt).octets)
        return distPoint.distributionPoints.flatMap { dp ->
            dp.distributionPoint?.let { dpn ->
                if (dpn.type == DistributionPointName.FULL_NAME) {
                    GeneralNames.getInstance(dpn.name).names.filter { it.tagNo == GeneralName.uniformResourceIdentifier }
                        .map { DERIA5String.getInstance(it.name).string }
                } else emptyList()
            } ?: emptyList()
        }
    }
}