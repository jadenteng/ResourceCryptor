//
//  ResourceCryptor.h
//  ResourceX
//
//  Created by dqdeng on 2020/4/8.
//  Copyright © 2020 Jaden. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "R_SA.h"

NS_ASSUME_NONNULL_BEGIN

/// key 加密密钥 iv IV向量
typedef NSData *_Nullable(^CRYPTOR_BLOCK)(NSString *key, NSString *_Nullable iv);
/// key 加密密钥 iv IV向量
typedef NSString *_Nullable(^CRYPTOR_STR_BLOCK)(NSString *key, NSString *_Nullable iv);
/// SHAHMAC key 加密密钥
typedef NSString *_Nullable(^k_CCHmacAlgSHA_block)(NSString *key);

#pragma mark - NSData AES DES 加密 解密
@interface NSData (ResourceCryptor)

/// DES 加密  key 加密密钥 iv  IV向量
@property (nonatomic,assign,readonly) CRYPTOR_BLOCK EN_DES;
/// DES 解密  key 解密密钥 iv  IV向量
@property (nonatomic,assign,readonly) CRYPTOR_BLOCK DE_DES;
/// AES 加密  key 加密密钥 iv  IV向量
@property (nonatomic,assign,readonly) CRYPTOR_BLOCK EN_AES;
/// AES 解密  key 解密密钥 iv  IV向量
@property (nonatomic,assign,readonly) CRYPTOR_BLOCK DE_AES;

/// data 转换为 json
@property (nonatomic,assign,readonly) id _Nonnull JSON_Object;

@end
#pragma mark - NSString AES DES 加密 解密 MD5 SHA256

@interface NSString (ResourceCryptor)

/// DES 加密  key 加密密钥 iv  IV向量
@property (nonatomic,assign,readonly) CRYPTOR_STR_BLOCK EN_DES;
/// DES 解密  key 解密密钥 iv  IV向量
@property (nonatomic,assign,readonly) CRYPTOR_STR_BLOCK DE_DES;
/// AES 加密  key 加密密钥 iv  IV向量
@property (nonatomic,assign,readonly) CRYPTOR_STR_BLOCK EN_AES;
/// AES 解密  key 解密密钥 iv  IV向量
@property (nonatomic,assign,readonly) CRYPTOR_STR_BLOCK DE_AES;
/// MD5加密
@property (nonatomic,assign,readonly)NSString *MD_5;
/// SHA_1 加密
@property (nonatomic,assign,readonly)NSString *SHA_1;
/// SHA_256 加密
@property (nonatomic,assign,readonly)NSString *SHA_256;
/// SHA_224 加密
@property (nonatomic,assign,readonly)NSString *SHA_224;
/// SHA_384 加密
@property (nonatomic,assign,readonly)NSString *SHA_384;
/// SHA_512 加密
@property (nonatomic,assign,readonly)NSString *SHA_512;

/// HMAC加密
/// SHA_256 by:key 加密
@property (nonatomic,assign,readonly)k_CCHmacAlgSHA_block SHA_256_HMAC_block;
/// SHA_MD5 by:key 加密密钥
@property (nonatomic,assign,readonly)k_CCHmacAlgSHA_block SHA_MD5_HMAC_block;
/// SHA_1 by:key   加密密钥
@property (nonatomic,assign,readonly)k_CCHmacAlgSHA_block SHA_1_HMAC_block;
/// SHA_224 by:key 加密密钥
@property (nonatomic,assign,readonly)k_CCHmacAlgSHA_block SHA_224_HMAC_block;
/// SHA_384 by:key 加密密钥
@property (nonatomic,assign,readonly)k_CCHmacAlgSHA_block SHA_384_HMAC_block;
/// SHA_512 by:key 加密密钥
@property (nonatomic,assign,readonly)k_CCHmacAlgSHA_block SHA_512_HMAC_block;

@end


@interface NSString (Conversion)
/// string to base64 string
@property (nonatomic,assign,readonly)NSString *base_64;
/// base64 转换为 普通string
@property (nonatomic,assign,readonly)NSString *encoding_base64;
/// base64string to base64 data
@property (nonatomic,assign,readonly)NSData *base_64_data;
/// string to utf8 data
@property (nonatomic,assign,readonly)NSData *utf_8; //
/// RSA string to data
@property (nonatomic,assign,readonly)NSData *rsa_data; //
/// data 转换为 json
@property (nonatomic,assign,readonly) id _Nonnull JSON_Object;
@end
@interface NSData (Conversion)
/// base64data 转为 base64 string
@property (nonatomic,assign,readonly)NSString *base64_encoded_string;
///// base64data 转为 base64 string
//@property (nonatomic,assign,readonly)NSString *base64_string;
/// base64data 转为 data
@property (nonatomic,assign,readonly)NSData *base64_encoded_data;
/// base64data 转换为utf8 string
@property (nonatomic,assign,readonly)NSString *encoding_base64_UTF8StringEncoding;

/// data 转换为 base64 data
@property (nonatomic,assign,readonly)NSData *base64_data;

@end

@interface NSDictionary (Conversion)
///将json数据 转为 base64 data
@property (nonatomic,assign,readonly) NSData *json_Data_utf8;
@property (nonatomic,assign,readonly) NSString *json_String;
@end
@interface NSData (Private)

/// DES 加密
/// @param key 加密密钥
/// @param iv  IV向量
- (NSData *)DES_EN:(NSString *)key iv:(NSString *)iv;

/// DES 解密
/// @param key 解密密钥
/// @param iv  IV向量
- (NSData *)DES_DE:(NSString *)key iv:(NSString *)iv;


/// AES 加密
/// @param key 加密密钥
/// @param iv  IV向量
- (NSData *)AES_EN:(NSString *)key iv:(NSString *)iv;

/// AES 解密
/// @param key 解密密钥
/// @param iv  IV向量
- (NSData *)AES_DE:(NSString *)key iv:(NSString *)iv;


@end

@interface NSString (Private)

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



NS_ASSUME_NONNULL_END
