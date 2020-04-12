
<p align="center">
<img src="https://github.com/JadenTeng/ResourceCryptor/blob/master/banner.jpg" width="232" height="42"/>
</p>

<p align="center">

<a href="https://github.com/JadenTeng/ResourceCryptor">
<img src="https://travis-ci.com/JadenTeng/ResourceCryptor.svg?branch=master">
</a>

<a href="https://codecov.io/gh/JadenTeng/ResourceCryptor">
  <img src="https://codecov.io/gh/JadenTeng/ResourceCryptor/branch/master/graph/badge.svg" />
</a>

<a href="https://github.com/Carthage/Carthage/">
   <img src="https://img.shields.io/badge/Carthage-Compatible-4BC51D">
</a>

<a href="https://github.com/CocoaPods/CocoaPods">
   <img src="https://img.shields.io/badge/CocoaPods-Compatible-orange">
</a>

</P>

`ResourceCryptor` Simplest `RSA` `AES` `DES` encrypt / decrypt with Objective-C on iOS and  `MD5` `SHA_1` `SHA_256` `SHA_224` `SHA_512` and HMAC `HmacMD5` `HmacSHA1_SHA224_SHA256_SHA384_SHA512` of NSData、NSString Category 

## Features
- [x] Fully tested.
- [x] Simple interface.
- [x] Support access group.
- [x] Support accessibility.
- [x] Support latest sdk 

### ResourceCryptor
- 对于Object-C的加密代码过于冗杂,作者把常见的加密的一些方法重新做了封装让对于加密解密变的更加简单好用,如果你正在为使用一些常规的加密方法过于复杂,相信ResourceCryptor会让您加密的逻辑处理变得更加容易。

* 使用RSA 加密解密提供了最简单的单例 `RSA_` 在库中的`R_SA.h` 
* 提供常规AES DES加解密 SHA_256 MD5等... 在ResourceCryptor.h中

#### *RSA* (encrypt)加密
 RSA 公钥为String或der证书类型
1. 加载RSA公钥 `add_pubKey`  or `add_pubPath`
```objective-c
// 1:加载公钥为String类型 
RSA_.add_pubKey(pubkey);
// 2:加载公钥 path:der格式的公钥证书
RSA_.add_pubPath(path);
```
2. 使用公钥加密
```objective-c
// 1:通过公钥加密content:文本类容
RSA_.EN_String(content)
// 2:通过公钥加密data:文本类容data
RSA_.EN_Data(data)
```
#### RSA (decrypt)解密
1. 加载RSA 密钥 
```objective-c
//1 通过privkey 为String类型 加载 
RSA_.add_privateKey(privkey);
//2 通过path 为der证书类型 加载 
RSA_.add_privatePath(path);
```
1. 解密RSA 
```objective-c
//en_str 解密的类容string
RSA_.DE_String(en_str)
//en_data 解密的类容data
RSA_.DE_String(en_data)
```
#### AES DES  EN加密与DE解密

AES 加解密 String `EN_AES(key,iv)`  key: 加密密钥 iv:  IV向量
```objective-c
//1.加密content文本 使用AES加密
 NSString *en_str = content.EN_AES(key,iv);
//2.解密文本 de_str:解密的内容
 NSString *de_str.DE_AES(key,iv)
```
AES 加解密 Data `EN_AES(key,iv)`  key: 加密密钥 iv:  IV向量
```objective-c
//1.加密json对象 使用AES加密
 NSData *en_data = json.EN_AES(key,iv);
//2.解密AES de_str:解密的data数据
 NSData *de_data.DE_AES(key,iv)
//3.转换为jsonObject
NSDictionary *jsonObj= de_data.DE_AES(key,iv)
```
DES 加解密 String `EN_DES(key,iv)`  key: 加密密钥 iv:  IV向量
```objective-c
//1.加密content文本 使用AES加密
 NSString *en_str = content.EN_DES(key,iv);
//2.解密文本 de_str:解密的内容
 NSString *de_str.DE_DES(key,iv)
```
DES 加解密 Data `EN_DES(key,iv)`  key: 加密密钥 iv:  IV向量
```objective-c
//1.加密json对象 使用AES加密
 NSData *en_data = json.EN_DES(key,iv);
//2.解密AES de_str:解密的data数据
 NSData *de_data.DE_DES(key,iv)
//3.转换为jsonObject
NSDictionary *jsonObj= de_data.DE_DES(key,iv)
```
#### HMAC 
1. MD_5 SHA_1 SHA_224 SHA_384 SHA_256 SHA_512
```objective-c
NSLog(@"MD_5:%@",string.MD_5);
NSLog(@"SHA_1:%@",string.SHA_1);
NSLog(@"SHA_224:%@",string.SHA_224);
NSLog(@"SHA_384:%@",string.SHA_384);
NSLog(@"SHA_256:%@",string.SHA_256);
NSLog(@"SHA_512:%@",string.SHA_512);
```
2.HMAC  SHA_MD5_HMAC SHA_256_HMAC SHA_1_HMAC SHA_224_HMAC SHA_384_HMAC SHA_512_HMAC
```objective-c
NSLog(@"MD_5:%@",string.SHA_MD5_HMAC_block(key));
NSLog(@"SHA_256:%@",string.SHA_256_HMAC_block(key));
NSLog(@"SHA_224:%@",@"hello".SHA_224_HMAC_block(key));
NSLog(@"SHA_1:%@",@"hello".SHA_1_HMAC_block(key));
```
### Carthage
```objective-c
github "JadenTeng/ResourceCryptor"
```
### CocoaPods
```ruby
pod 'ResourceCryptor'  
```
### 手动安装
将ResourceCryptor文件夹拽入项目中，导入头文件：#import "ResourceCryptor.h"

### Requirements
- iOS 9.0+

###  Release Notes 最近更新     
- 1.0 Initial release

