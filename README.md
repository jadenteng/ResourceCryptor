
<p align="center">
<img src="https://github.com/JadenTeng/ResourceCryptor/banner.jpg"/>
</p>

# ResourceCryptor

* RSA & AES & DES  Simplest NSData、NSString Category of  on iOS  SSL/TLS自签

对于Object-C一些加密代码的封装github上搜相信有很多,作者把这些加密的一些方法也是参考并重新做了封装,如果你正在为使用一些常规的加密方法过于复杂,相信ResourceCryptor会让加密的逻辑处理变得容易。


> RSA  1
```objective-c

    NSString *pem = @"expmle"; //使用RSA公钥加密的key(本地或者服务器获取)
    
   ///获取ResourceCryptor单例
   ResourceCryptor *cryptor = [ResourceCryptor share];
   
   // 1:加载公钥
   [cryptor rsa_public_key:pubkey];
   
   // 2:使用公钥加密
   NSString *en_str = [cryptor RSA_EN_String:pem];

   // 3:加载私钥
   [cryptor rsa_private_key:privkey];
   
   // 4:使用私钥解密
   NSString *de_data = [cryptor RSA_DE_String:en_str];
   
   NSLog(@"解密结果 %@", de_data);

```

> RSA 2

```objective-c

       //1:加载公钥
       [cryptor rsa_public_key_path:[[NSBundle mainBundle] pathForResource:@"rsacert.der" ofType:nil]];
       
       //2:使用公钥加密
       NSString *en_str = [cryptor RSA_EN_String:pem];
       NSLog(@"加密后结果:%@",en_str);
       
       //3:加载私钥,并且指定导出p12时设定的密码
       [cryptor rsa_private_key_path:[[NSBundle mainBundle] pathForResource:@"p.p12" ofType:nil] pwd:@"123456"];
       
       //4: 使用私钥解密
       NSString *de_data = [cryptor RSA_DE_String:en_str];

```

> DES

```objective-c
     
       NSString *str = @"hello !";
       // 1.加密
       NSString *en_str = [str DES_EN:key iv:iv];
       // 2.解密
       NSString *de_str = [en_str DES_DE:key iv:iv];
```
