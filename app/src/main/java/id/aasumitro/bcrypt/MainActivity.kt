package id.aasumitro.bcrypt

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import id.aasumitro.bcrypt.encrypt.BCrypt
import id.aasumitro.bcrypt.encrypt.BCryptPasswordEncoderImpl

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val hash = encryptPassword("password")

        Log.d("Password Hash", hash)

        if (verifyPassword("password", hash)) {
            Log.d("Password Hash", "It matches")
        } else {
            Log.d("Password Hash", "It does not match")
        }
    }
}
