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
@property (nonatomic,assign,readonly)R_SA_KEY_BLOCK  add_pubPath;
/// 公钥 字符串public_key
@property (nonatomic,assign,readonly)R_SA_KEY_BLOCK  add_pubKey;
///加载私钥 路径path
@property (nonatomic,assign,readonly)R_SA_PRIVATEKEY_BLOCK  add_privatePath;

/// 私钥 字符串private_key
@property (nonatomic,assign,readonly)R_SA_KEY_BLOCK  add_privateKey;

+ (instancetype)share;

@end



NS_ASSUME_NONNULL_END
