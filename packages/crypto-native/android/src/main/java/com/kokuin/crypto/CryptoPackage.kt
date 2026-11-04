package com.kokuin.crypto

import android.util.Log
import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager
import com.margelo.nitro.kokuin.crypto.KokuinCryptoOnLoad

class CryptoPackage : ReactPackage {
  companion object {
    private const val TAG = "KokuinCrypto"

    /**
     * Set when libKokuinCrypto.so could not be loaded, typically because the app was built for
     * an ABI the package does not ship (armeabi-v7a, x86). The `Crypto` hybrid object is then
     * not registered and `createNativeCrypto()` throws, instead of the app crashing on startup.
     */
    @JvmStatic
    var loadError: UnsatisfiedLinkError? = null
      private set

    init {
      try {
        KokuinCryptoOnLoad.initializeNative()
      } catch (error: UnsatisfiedLinkError) {
        loadError = error
        Log.w(TAG, "libKokuinCrypto.so is unavailable on this ABI; createNativeCrypto() will throw", error)
      }
    }
  }

  override fun createNativeModules(context: ReactApplicationContext): List<NativeModule> = emptyList()
  override fun createViewManagers(context: ReactApplicationContext): List<ViewManager<*, *>> = emptyList()
}
