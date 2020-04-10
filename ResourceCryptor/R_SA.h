//
//  R_SA.h
//  ResourceCryptor
//
//  Created by dqdeng on 2020/4/9.
//  Copyright © 2020 Jaden. All rights reserved.
//

#import <Foundation/Foundation.h>

#define RSA_ [R_SA share]

typedef NSData *_Nullable(^RSA_EN_DATA_BLOCK)(NSData *_Nullable data);
typedef NSString *_Nullable(^RSA_EN_STR_BLOCK)(NSString *_Nullable str);
typedef void(^R_SA_KEY_BLOCK)(NSString * _Nullable key);
/// path加载路径 pwd p12密码
typedef void(^R_SA_PRIVATEKEY_BLOCK)(NSString * _Nullable path,NSString * _Nullable pwd);

NS_ASSUME_NONNULL_BEGIN

@interface R_SA : NSObject

///加密 DATA 数据
@property (nonatomic,assign,readonly)RSA_EN_DATA_BLOCK EN_Data;
///加密 String
@property (nonatomic,assign,readonly)RSA_EN_STR_BLOCK  EN_String;
///解密 DATA 数据
@property (nonatomic,assign,readonly)RSA_EN_DATA_BLOCK DE_Data;
///解密 String
@property (nonatomic,assign,readonly)RSA_EN_STR_BLOCK  DE_String;
/// DER 公钥文件路径path pwd 加密的密码
@property (nonatomic,assign,readonly)R_SA_KEY_BLOCK  add_public_key_path;
/// 公钥 字符串public_key
@property (nonatomic,assign,readonly)R_SA_KEY_BLOCK  add_public_key;
///加载私钥 路径path
@property (nonatomic,assign,readonly)R_SA_PRIVATEKEY_BLOCK  add_private_key_path;

/// 私钥 字符串private_key
@property (nonatomic,assign,readonly)R_SA_KEY_BLOCK  add_private_key;

+ (instancetype)share;

@end

@interface R_SA (Private)
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

NS_ASSUME_NONNULL_END
