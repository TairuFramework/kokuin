#include <fbjni/fbjni.h>
#include "KokuinCryptoOnLoad.hpp"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return facebook::jni::initialize(vm, [] {
    margelo::nitro::kokuin::crypto::registerAllNatives();
  });
}
