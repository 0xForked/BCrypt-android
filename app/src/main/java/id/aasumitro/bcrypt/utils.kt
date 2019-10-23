package id.aasumitro.bcrypt

import id.aasumitro.bcrypt.encrypt.BCryptPasswordEncoderImpl
import id.aasumitro.bcrypt.encrypt.BCryptVersion


/**
 * Created by A. A. Sumitro on 23/10/19.
 * hello@aasumitro.id
 */

fun encryptPassword(key: String) =  BCryptPasswordEncoderImpl(
    BCryptVersion.`$2Y`
).encode(key)

fun verifyPassword(
    rawPassword: CharSequence,
    encodedPassword: String
) = BCryptPasswordEncoderImpl().matches(rawPassword, encodedPassword)