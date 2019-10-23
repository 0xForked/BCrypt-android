package id.aasumitro.bcrypt

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import id.aasumitro.bcrypt.encrypt.BCrypt
import id.aasumitro.bcrypt.encrypt.BCryptPasswordEncoder

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val hash = BCryptPasswordEncoder(
            BCryptPasswordEncoder.BCryptVersion.`$2Y`
        ).encode("secret")

        Log.d("Password Hash", hash)

        if (BCrypt.checkpw("secret", hash)) {
            Log.d("Password Hash", "It matches")
        } else {
            Log.d("Password Hash", "It does not match")
        }
    }
}
