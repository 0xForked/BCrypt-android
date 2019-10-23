package id.aasumitro.bcrypt.encrypt

/**
 * Created by A. A. Sumitro on 23/10/19.
 * hello@aasumitro.id
 *
 * Stores the default bcrypt version for use in configuration.
 */

enum class BCryptVersion constructor(val version: String) {
    `$2A`("$2a"),
    `$2Y`("$2y"),
    `$2B`("$2b")
}
