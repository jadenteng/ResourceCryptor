Pod::Spec.new do |spec|

  spec.name         = "ResourceCryptor"
  spec.version      = "1.0.1"
  spec.summary      = "iOS RSA DES AES MD5 SHA_1 SHA225 SHA_256 SHA_224 SHA_384 ..."
  spec.homepage     = "https://github.com/JadenTeng/ResourceCryptor.git"
  spec.license      = "MIT"
  spec.license      = { :type => "MIT", :file => "LICENSE" }
  spec.author             = { "JadenTeng" => "781232284@qq.com" }
  spec.platform     = :ios, "9.0"
  spec.source       = { :git => "https://github.com/JadenTeng/ResourceCryptor.git", :tag => "#{spec.version}" }
  spec.source_files  = "ResourceCryptor", "ResourceCryptor/**/*.{h,m}"
 # spec.requires_arc = true

end
