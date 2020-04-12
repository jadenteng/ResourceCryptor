
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
- [x] Support access group and accessibility.

## 上手指南
> 对于Object-C的加密代码过于冗杂,作者把常见的加密的一些方法重新做了封装让对于加密解密变的更加简单好用,如果你正在为使用一些常规的加密方法过于复杂,相信ResourceCryptor会让您加密的逻辑处理变得更加容易。

* 使用RSA 加密解密提供了最简单的单例 `RSA_` 在库中的`R_SA.h` 
* 提供常规AES DES加解密 SHA_256 MD5等... 在ResourceCryptor.h中
* RSA 如何生成公钥、密钥以及.der .p12证书放在文章末尾

#### **RSA (encrypt)加密**
##### RSA 公钥为String或der证书类型
> 1. 加载RSA公钥 `add_pubKey`  or `add_pubPath`
```objective-c
// 1:加载公钥为String类型 
RSA_.add_pubKey(pubkey);
// 2:加载公钥 path:der格式的公钥证书
RSA_.add_pubPath(path);
```
> 2. 使用公钥加密
```objective-c
// 1:通过公钥加密content:文本类容
RSA_.EN_String(content)
// 2:通过公钥加密data:文本类容data
RSA_.EN_Data(data)
```
#### RSA (decrypt)解密
>  1. 加载RSA 密钥 
```objective-c
//1 通过privkey 为String类型 加载 
RSA_.add_privateKey(privkey);
//2 通过path 为der证书类型 加载 
RSA_.add_privatePath(path);
```
>  2. 解密RSA 
```objective-c
//en_str 解密的类容string
RSA_.DE_String(en_str)
//en_data 解密的类容data
RSA_.DE_String(en_data)
```
#### AES DES  EN加密与DE解密

* AES 加解密 String `EN_AES(key,iv)`  key: 加密密钥 iv:  IV向量
```objective-c
//1.加密content文本 使用AES加密
NSString *en_str = content.EN_AES(key,iv);
//2.解密文本 de_str:解密的内容
NSString *de_str.DE_AES(key,iv)
```
- AES 加解密 Data `EN_AES(key,iv)`  key: 加密密钥 iv:  IV向量
```objective-c
//1.加密json对象 使用AES加密
NSData *en_data = json.EN_AES(key,iv);
//2.解密AES de_str:解密的data数据
NSData *de_data.DE_AES(key,iv)
//3.转换为jsonObject
NSDictionary *jsonObj= de_data.DE_AES(key,iv)
```
- DES 加解密 String `EN_DES(key,iv)`  key: 加密密钥 iv:  IV向量
```objective-c
//1.加密content文本 使用DES加密
NSString *en_str = content.EN_DES(key,iv);
//2.解密文本 de_str:解密的内容
NSString *de_str.DE_DES(key,iv)
```
- DES 加解密 Data `EN_DES(key,iv)`  key: 加密密钥 iv:  IV向量
```objective-c
//1.加密json对象 使用DES加密
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
2. HMAC  SHA_MD5_HMAC SHA_256_HMAC SHA_1_HMAC SHA_224_HMAC SHA_384_HMAC SHA_512_HMAC
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

### 参考文档 以及代码
>![自签名证书](http://www.demodashi.com/demo/14102.html)
>![XHCryptorTools](https://github.com/XHTeng/XHCryptorTools)

# 加密介绍
>`ResourceCryptor` 使用苹果系统自带相关函数进行加密解密
>对于普遍APP的加密方式:客户端用RSA的公钥加密AES密钥,服务器端用私钥解密从app获得的AES密钥,客户端再与服务器进行AES加密的数据传输。
---
>加密解密概念
* 对称加密算法：加密解密都使用相同的秘钥，速度快，适合对大数据加密，方法有DES，3DES，AES等
* 非对称加密算法
非对称加密算法需要两个密钥：公开密钥（publickey）和私有密钥（privatekey）
公开密钥与私有密钥是一对，可逆的加密算法，用公钥加密，用私钥解密，用私钥加密，用公钥解密，速度慢，适合对小数据加密，方法有RSA
* 散列算法（加密后不能解密，上面都是可以解密的）
用于密码的密文存储，服务器端是判断加密后的数据
不可逆加密方法：MD5、SHA1、SHA256、SHA512

> RSA算法原理：
 1. 找出两个“很大”的质数：P & Q（上百位）
N = P * Q
M = (P – 1) * (Q – 1)
 2. 找出整数E，E与M互质，即除了1之外，没有其他公约数
 3. 找出整数D，使得 ED 除以 M 余 1，即 (E * D) % M = 1
 4. 经过上述准备工作之后，可以得到：E是公钥，负责加密D是私钥，负责解密N负责公钥和私钥之间的联系
 5. 加密算法，假定对X进行加密(X ^ E) % N = Y（6）解密算法，根据费尔马小定义，可以使用以下公式完成解密(Y ^ D) % N = X
---
# 关于如何生成: 公钥、私钥 、der证书签名
>公钥:签名机构签完给我们颁发的，放在网站的根目录上，可以分发
私钥：一般保存在中心服务器

注: RSA为一种加密算法，生成的文件格式有两种，一种是PEM格式，另一种是DER格式
在Mac OSX 里面，pem格式是不能打开的，因此我们生成PEM文件之后，需要生成DER格式。

###### 加密解密使用了两种文件 .p12是私钥  .der是公钥，终端命令生成步骤如下：
1. 打开终端
`openssl`
2. 创建私钥
`genrsa -out rsa_private_key.pem 1024 `
3. 生成公钥
`rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem`
4. 生成证书请求文件.csr  …输入信息 …输入密码
`req -new -key rsa_private_key.pem -out ca.csr`  
>终端提示如下：
* 国家名字、代码
* 省的名字
* 城市的名字
* 公司的名字
* 公司的单位
* 我的名字
* 电子邮件
* 以及两个附加信息可以跳过

5. 签名 生成一个.crt的一个base64公钥文件 
`x509 -req -days 3650 -in ca.csr -signkey rsa_private_key.pem -out ca.crt`
6. 解成.der公钥二进制文件，放程序做加密用
`x509 -outform der -in ca.crt -out ca.der`
7. 生成.p12二进制私钥文件 .pem 是base64的不能直接使用，必须导成.p12信息交换文件用来传递秘钥
`pkcs12 -export -out p.p12 -inkey rsa_private_key.pem -in ca.crt` (输入一个导出密码框架中pwd参数需要用的密码）)

![生成如下证书文件](https://github.com/JadenTeng/ResourceCryptor/blob/master/ca.jpg)

#  对于数据加密解密+网络请求(基于AF封装) ![ResourceX](https://github.com/JadenTeng/ResourceX)
> ***欢迎使用我的另外的库***![ResourceX](https://github.com/JadenTeng/ResourceX)

###  Release Notes 最近更新     
- 1.0 Initial release

