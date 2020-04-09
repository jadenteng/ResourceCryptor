//
//  ResourceCryptor.h
//  ResourceX
//
//  Created by dqdeng on 2020/4/8.
//  Copyright © 2020 Jaden. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ResourceCryptor : NSObject

#pragma mark - RSA 加密/解密算法

+ (instancetype)share;
/// 加载公钥
/// @param path  DER 公钥文件路径
- (void)rsa_public_key_path:(NSString *)path;
- (void)rsa_public_key:(NSString *)key;
/// 加载私钥
/// @param path P12 私钥文件路径
/// @param pwd P12 密码
- (void)rsa_private_key_path:(NSString *)path pwd:(NSString *)pwd;
- (void)rsa_private_key:(NSString *)key;

/// RSA 加密数据
/// @param data 加密后的二进制数据
- (NSData *)RSA_EN_Data:(NSData *)data;


///  RSA 加密字符串
/// @param string 要加密的字符串
- (NSString *)RSA_EN_String:(NSString *)string;


/// RSA 解密数据
/// @param data 要解密的数据
- (NSData *)RSA_DE_Data:(NSData *)data;


/// RSA 解密字符串
/// @param string 要解密的 BASE64 编码字符串
- (NSString *)RSA_DE_String:(NSString *)string;

@end


@interface NSData (ResourceCryptor)

#pragma mark - DES 加密/解密

/// DES 加密
/// @param key 加密密钥
/// @param iv  IV向量
- (NSData *)DES_EN:(NSString *)key iv:(NSString *)iv;

/// DES 解密
/// @param key 解密密钥
/// @param iv  IV向量
- (NSData *)DES_DE:(NSString *)key iv:(NSString *)iv;

#pragma mark - AES 加密/解密

/// AES 加密
/// @param key 加密密钥
/// @param iv  IV向量
- (NSData *)AES_EN:(NSString *)key iv:(NSString *)iv;

/// AES 解密
/// @param key 解密密钥
/// @param iv  IV向量
- (NSData *)AES_DE:(NSString *)key iv:(NSString *)iv;

@end

typedef NSString *_Nullable(^CC_SHA256Block)(NSString *key);

@interface NSString (ResourceCryptor)

/// MD5加密
@property (nonatomic,assign,readonly)NSString *MD_5;
@property (nonatomic,assign,readonly)NSString *SHA_256;
/// SHA_256 by:key 加密
@property (nonatomic,assign,readonly)CC_SHA256Block SHA_256_block;
/// AES 加密
/// @param key 加密密钥
/// @param iv  IV向量
- (NSString *)AES_EN:(NSString *)key iv:(NSString *)iv;

/// AES 解密
/// @param key 解密密钥
/// @param iv  IV向量
- (NSString *)AES_DE:(NSString *)key iv:(NSString *)iv;

/// DES 加密
/// @param key 加密密钥
/// @param iv  IV向量
- (NSString *)DES_EN:(NSString *)key iv:(NSString *)iv;
/// DES 解密
/// @param key 解密密钥
/// @param iv  IV向量
- (NSString *)DES_DE:(NSString *)key iv:(NSString *)iv;

@end

@interface NSString (Conversion)
/// string to base64 string
@property (nonatomic,assign,readonly)NSString *base_64;
/// base64 转换为 普通string
@property (nonatomic,assign,readonly)NSString *encoding_base64;
/// string to base64 data
@property (nonatomic,assign,readonly)NSData *base_64_data;
/// string to utf8 data
@property (nonatomic,assign,readonly)NSData *utf_8; //
@end
@interface NSData (Conversion)
/// base64 string
@property (nonatomic,assign,readonly)NSString *base64_encoded_string;
/// data 转换为utf8
@property (nonatomic,assign,readonly)NSString *encoding_base64_UTF8StringEncoding;
@end
NS_ASSUME_NONNULL_END
