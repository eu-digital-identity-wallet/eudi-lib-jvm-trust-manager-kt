package eu.europa.ec.eudi.trustmanager.internal

import eu.europa.ec.eudi.trustmanager.CRLValidationResult
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import kotlin.test.Test

class CRLValidatorImplTest {

    @Test
    fun validateCRL() = runBlocking {

        val sampleIACACertificate = CertificateFactory.getInstance("X.509").generateCertificate(
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

        val sampleDsCertificate = CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(
                Base64.getDecoder().decode(
                    String(
                        ClassLoader.getSystemResourceAsStream("eudi_ds_pem")?.readAllBytes()!!
                    ).replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "")
                        .replace("\n", "")
                        .replace("\r", "")
                )
            )
        ) as X509Certificate

        val currentDate = Date()
        val crlValidation = CRLValidatorImpl()
            .withCurrentDate(currentDate)

        val result = crlValidation.validateCRL(sampleDsCertificate, sampleIACACertificate)

        assert(result is CRLValidationResult.Success)
    }
}