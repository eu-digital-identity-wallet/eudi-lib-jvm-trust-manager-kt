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

import eu.europa.ec.eudi.trustmanager.internal.TrustStoreImpl
import java.security.cert.X509Certificate
import java.util.*

/**
 * This class represents the configuration for a TrustManager.
 *
 * @property builder The builder instance used to construct the TrustManagerConfig.
 */
class TrustManagerConfig private constructor(private val builder: Builder) {

    /**
     * The trustStore property is a getter that retrieves the trustStore from the builder.
     */
    val trustStore: TrustStore
        get() = builder.trustStore

    /**
     * The currentDate property is a getter that retrieves the currentDate from the builder.
     */
    val currentDate: Date
        get() = builder.currentDate

    /**
     * The crlValidationEnabled property is a getter that retrieves the crlValidationEnabled from the builder.
     */
    val crlValidationEnabled: Boolean
        get() = builder.crlValidationEnabled

    /**
     * The Builder class is used to construct a TrustManagerConfig instance.
     */
    class Builder {

        /**
         * The trustStore property is a lateinit var, meaning it must be initialized before it's used.
         * It is private to the Builder class and can only be set through the withTrustStore methods.
         */
        lateinit var trustStore: TrustStore
            private set

        var currentDate: Date = Date()

        var crlValidationEnabled: Boolean = true

        /**
         * This method sets the trustStore property to the provided TrustStore instance.
         *
         * @param trustStore The TrustStore instance to be used.
         */
        fun withTrustStore(trustStore: TrustStore) = apply { this.trustStore = trustStore }

        /**
         * This method sets the trusted root CA certificates to be used in the TrustStore.
         *
         * @param trustedCertificates The trusted root CA certificates to be used in the TrustStore.
         */
        fun withTrustStore(trustedCertificates: List<X509Certificate>) = apply {
            this.trustStore = TrustStoreImpl(trustedCertificates)
        }

        /**
         * This method sets the current date to be used for validation.
         *
         * @param currentDate The current date to be used for validation.
         */
        fun withCurrentDate(currentDate: Date) = apply {
            this.currentDate = currentDate
        }

        /**
         * This method sets whether CRL validation is enabled or not.
         *
         * @param crlValidationEnabled A boolean value indicating whether CRL validation is enabled or not.
         */
        fun withCRLValidationEnabled(crlValidationEnabled: Boolean) = apply {
            this.crlValidationEnabled = crlValidationEnabled
        }

        /**
         * This method builds and returns a TrustManagerConfig instance.
         *
         * @throws IllegalArgumentException If the trustStore property is not initialized or if it doesn't contain any trusted roots.
         * @return Returns a TrustManagerConfig instance.
         */
        fun build(): TrustManagerConfig {
            require(this::trustStore.isInitialized && trustStore.trustedRoots.isNotEmpty()) { "TrustManagerConfig: trustStore must be defined" }
            (trustStore as? TrustStoreImpl)?.apply {
                withCurrentDate(currentDate)
                withCRLValidationEnabled(crlValidationEnabled)

            }
            return TrustManagerConfig(this)
        }
    }
}