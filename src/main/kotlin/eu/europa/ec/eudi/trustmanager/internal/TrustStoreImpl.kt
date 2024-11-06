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
import eu.europa.ec.eudi.trustmanager.CertificatePathVerificationResult
import eu.europa.ec.eudi.trustmanager.CertificateVerificationError
import eu.europa.ec.eudi.trustmanager.TrustStore
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.security.cert.*
import java.util.*

internal class TrustStoreImpl(
    override val trustedRoots: List<X509Certificate>,
    private var crlValidator: CRLValidator = CRLValidatorImpl(),
    private var crlValidationEnabled: Boolean = true,
    private var currentDate: Date = Date(),
) : TrustStore {

    fun withCRLValidator(crlValidator: CRLValidator): TrustStoreImpl {
        this.crlValidator = crlValidator
        return this
    }

    fun withCRLValidationEnabled(crlValidationEnabled: Boolean): TrustStoreImpl {
        this.crlValidationEnabled = crlValidationEnabled
        return this
    }

    fun withCurrentDate(currentDate: Date): TrustStoreImpl {
        this.currentDate = currentDate
        return this
    }

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    override suspend fun validateCertificatePath(chain: List<X509Certificate>): CertificatePathVerificationResult {
        try {
            val trustAnchors = trustedRoots.map { trustedCert ->
                TrustAnchor(trustedCert, null)
            }.toSet()

            val certStore =
                CertStore.getInstance("Collection", CollectionCertStoreParameters(trustAnchors))

            val pkixParams = PKIXBuilderParameters(trustAnchors, X509CertSelector()).apply {
                addCertStore(certStore)
                date = currentDate
                isRevocationEnabled = false
            }

            val certificateFactory =
                CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
            val certPath = certificateFactory.generateCertPath(chain) as CertPath

            val certPathValidatorResult =
                CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME)
                    .validate(certPath, pkixParams) as PKIXCertPathValidatorResult

            if (crlValidationEnabled) {
                val crlValidationResult = crlValidator.validateCRL(
                    chain.first(),
                    certPathValidatorResult.trustAnchor.trustedCert as X509Certificate
                )
                if (crlValidationResult is CRLValidationResult.Failure)
                    return CertificatePathVerificationResult.Failure(crlValidationResult.error)
            }
            return CertificatePathVerificationResult.Success
        } catch (e: CertPathValidatorException) {
            return CertificatePathVerificationResult.Failure(
                CertificateVerificationError.CertificatePathVerificationError(
                    "Certificate path validation failed: ${e.message}"
                )
            )
        } catch (e: Exception) {
            return CertificatePathVerificationResult.Failure(
                CertificateVerificationError.CertificatePathVerificationError(
                    "Certificate path validation failed: ${e.message}"
                )
            )
        }
    }
}