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

import eu.europa.ec.eudi.trustmanager.internal.CRLValidatorImpl
import eu.europa.ec.eudi.trustmanager.internal.IssuerDataAuthenticationImpl
import eu.europa.ec.eudi.trustmanager.internal.TrustStoreImpl

/**
 * The TrustManager class is responsible for verifying data, e.g. IsuuerSignedData.
 * It uses a configuration object of type TrustManagerConfig to get the necessary trust store for verification.
 *
 * @property config The configuration object containing the trust store.
 */
class TrustManager(private val config: TrustManagerConfig) :
    Verifier<IssuerSignedData> by IssuerDataAuthenticationImpl(
        config.trustStore,
        config.currentDate
    ),
    TrustStore by config.trustStore,
    CRLValidator by CRLValidatorImpl(config.currentDate) {

    init {
        if (config.trustStore is TrustStoreImpl) {
            (config.trustStore as TrustStoreImpl).apply {
                withCRLValidator(this@TrustManager)
                withCurrentDate(config.currentDate)
                withCRLValidationEnabled(config.crlValidationEnabled)
            }
        }
    }

    /**
     * Companion object to create a new instance of TrustManager.
     */
    companion object {
        /**
         * Creates a new instance of TrustManager.
         */
        operator fun invoke(configure: TrustManagerConfig.Builder.() -> Unit): TrustManager {
            val builder = TrustManagerConfig.Builder().apply(configure)
            return TrustManager(builder.build())
        }
    }
}