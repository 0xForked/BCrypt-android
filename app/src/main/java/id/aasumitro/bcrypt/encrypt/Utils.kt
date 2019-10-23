package id.aasumitro.bcrypt.encrypt


/**
 * Created by A. A. Sumitro on 23/10/19.
 * hello@aasumitro.id
 */

fun illegalFormatMessage(): String? {
    throw IllegalBCryptFormatException(" - example of expected hash format: " +
            "'$2a$06\$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i'" +
            " which includes 16 bytes salt and 23 bytes hash value encoded in a base64 flavor")
}