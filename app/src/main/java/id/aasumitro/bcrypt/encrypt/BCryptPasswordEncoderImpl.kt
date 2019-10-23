package id.aasumitro.bcrypt.encrypt

/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import android.util.Log

import java.security.SecureRandom
import java.util.regex.Pattern

/**
 * Implementation of PasswordEncoder that uses the BCrypt strong hashing function. Clients
 * can optionally supply a "version" ($2a, $2b, $2y) and a "strength" (a.k.a. log rounds in BCrypt)
 * and a SecureRandom instance. The larger the strength parameter the more work will have to be done
 * (exponentially) to hash the passwords. The default value is 10.
 *
 * @author Dave Syer
 */

/**
 * Modified by A. A. Sumitro on 23/10/19.
 */

class BCryptPasswordEncoderImpl
/**
 * @param version  the version of bcrypt, can be 2a,2b,2y
 * @param strength the log rounds to use, between 4 and 31
 * @param random   the secure random instance to use
 */
@JvmOverloads constructor(
    private val version: BCryptVersion,
    strength: Int,
    private val random: SecureRandom? = null
) : PasswordEncoder {

    companion object {
        val BCRYPT_PATTERN: Pattern = Pattern
            .compile("\\A\\$2([ayb])?\\$(\\d\\d)\\$[./0-9A-Za-z]{53}")
    }

    private val strength: Int

    /**
     * @param version the version of bcrypt, can be 2a,2b,2y
     * @param random  the secure random instance to use
     */
    @JvmOverloads
    constructor(
        version: BCryptVersion,
        random: SecureRandom? = null
    ) : this(version, -1, random)

    /**
     * @param strength the log rounds to use, between 4 and 31
     * @param random   the secure random instance to use
     */
    @JvmOverloads
    constructor(strength: Int = -1, random: SecureRandom? = null) : this(
        BCryptVersion.`$2A`,
        strength,
        random
    )

    init {
        require(!(strength != -1 && (strength < BCrypt.MIN_LOG_ROUNDS ||
                strength > BCrypt.MAX_LOG_ROUNDS))) { "Bad strength" }
        this.strength = if (strength == -1) 10 else strength
    }

    override fun encode(rawPassword: CharSequence): String {
        val salt: String = if (random != null) {
            BCrypt.gensalt(version.version, strength, random)
        } else {
            BCrypt.gensalt(version.version, strength)
        }
        return BCrypt.hashpw(rawPassword.toString(), salt)
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String): Boolean {
        if (encodedPassword.isEmpty()) {
            Log.d("BCryptPasswordEncoder", "Empty encoded password")
            return false
        }

        if (!BCRYPT_PATTERN.matcher(encodedPassword).matches()) {
            Log.d("BCryptPasswordEncoder", "Encoded password does not look like BCrypt")
            return false
        }

        return BCrypt.checkpw(rawPassword.toString(), encodedPassword)
    }

    override fun upgradeEncoding(encodedPassword: String): Boolean {
        if (encodedPassword.isEmpty()) {
            Log.d("BCryptPasswordEncoder", "Empty encoded password")
            return false
        }

        val matcher = BCRYPT_PATTERN.matcher(encodedPassword)
        require(matcher.matches()) { "Encoded password does not look like BCrypt: $encodedPassword" }
        val strength = Integer.parseInt(matcher.group(2) as String)
        return strength < this.strength
    }

    /**
     * Stores the default bcrypt version for use in configuration.
     *
     * @author Lin Feng
     */
    enum class BCryptVersion constructor(val version: String) {
        `$2A`("$2a"),
        `$2Y`("$2y"),
        `$2B`("$2b")
    }
}
