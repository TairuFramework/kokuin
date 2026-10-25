require 'json'
package = JSON.parse(File.read(File.join(__dir__, 'package.json')))

Pod::Spec.new do |spec|
  spec.name = 'KokuinCrypto'
  spec.version = package['version']
  spec.summary = package['description']
  spec.homepage = 'https://github.com/TairuFramework/kokuin'
  spec.license = 'MIT'
  spec.author = 'Paul Le Cam'
  spec.source = { :git => 'https://github.com/TairuFramework/kokuin.git', :tag => spec.version.to_s }
  spec.platforms = { :ios => '16.4' }
  spec.source_files = 'cpp/**/*.{h,hpp,cpp}'
  spec.exclude_files = 'cpp/test/**/*'
  spec.vendored_frameworks = 'prebuilt/ios/KokuinCrypto.xcframework'
  spec.libraries = 'c++', 'resolv'
  load File.join(__dir__, 'nitrogen/generated/ios/KokuinCrypto+autolinking.rb')
  add_nitrogen_files(spec)
  install_modules_dependencies(spec)
end
