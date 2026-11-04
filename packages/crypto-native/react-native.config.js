export default {
  dependency: {
    platforms: {
      ios: {},
      android: {
        sourceDir: './android',
        packageImportPath: 'import com.kokuin.crypto.CryptoPackage;',
        packageInstance: 'new CryptoPackage()',
      },
    },
  },
}
