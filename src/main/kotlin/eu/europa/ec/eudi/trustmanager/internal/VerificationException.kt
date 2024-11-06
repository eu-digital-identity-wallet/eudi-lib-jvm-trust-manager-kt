package eu.europa.ec.eudi.trustmanager.internal

import eu.europa.ec.eudi.trustmanager.VerificationError

internal data class VerificationException(val error: VerificationError) : RuntimeException()

internal fun VerificationError.asException(): VerificationException =
    VerificationException(this)