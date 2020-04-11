//
//  R_SA.m
//  ResourceCryptor
//
//  Created by dqdeng on 2020/4/9.
//  Copyright © 2020 Jaden. All rights reserved.
//

#import "R_SA.h"
#import <CommonCrypto/CommonCrypto.h>
#import "ResourceCryptor.h"

// 填充模式
#define kTypeOfWrapPadding        kSecPaddingPKCS1
typedef BOOL (^Array_Filter_Block)(id );

@interface NSData (RSA)
@property (nonatomic,readonly,assign)NSData *rsa_public_data; //
@property (nonatomic,readonly,assign)NSData *rsa_private_data; //
@end
@interface NSArray (filter)
@end

static R_SA *shareInstance = nil;

@interface R_SA() {
    SecKeyRef _publicKeyRef;                             // 公钥引用
    SecKeyRef _privateKeyRef;                            // 私钥引用
}

@end


@implementation NSArray (filter)

- (NSMutableArray *)filter:(Array_Filter_Block)predicate {
    NSMutableArray *list = [NSMutableArray arrayWithCapacity:self.count];
    [self enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        if (predicate(obj)) {
            [list addObject:obj];
        }
    }];
    return list;
}

@end

@implementation R_SA

+ (instancetype)share {
    if (shareInstance == nil) {
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            shareInstance = [[R_SA alloc] init];
        });
    }
    return shareInstance;
}

#pragma mark - RSA 加密/解密算法

- (R_SA_KEY_BLOCK)add_public_key_path {
    return ^(NSString *path) {
        [self rsa_public_key_path:path];
    };
}
- (R_SA_PRIVATEKEY_BLOCK)add_private_key_path {
    return ^(NSString *path,NSString *pwd) {
        [self rsa_private_key_path:path pwd:pwd];
    };
}

- (R_SA_KEY_BLOCK)add_public_key {
    return ^(NSString *key) {
        [self  rsa_public_key:key];
    };
}
- (R_SA_KEY_BLOCK)add_private_key {
    return ^(NSString *key) {
        [self  rsa_private_key:key];
    };
}

/// 加密str
- (RSA_EN_STR_BLOCK)EN_String {
    return ^(NSString *str){
        return [self RSA_EN_String:str];
    };
}
///解密data
- (RSA_EN_DATA_BLOCK)EN_Data {
    return ^(NSData *data){
        return [self RSA_EN_Data:data];
    };
}

/// 加密data
- (RSA_EN_DATA_BLOCK)DE_Data{
    return ^(NSData *data){
        return [self RSA_DE_Data:data];
    };
}

/// 解密str
- (RSA_EN_STR_BLOCK)DE_String {
    return ^(NSString *str) {
        return [self RSA_DE_String:str];
    };
}

@end


@implementation R_SA (Private)

- (NSString *)RSA_EN_String:(NSString *)string {
    return [self RSA_EN_Data:string.utf_8].base64_encoded_string;
}

- (NSString *)RSA_DE_String:(NSString *)string {
    return [self RSA_DE_Data:string.base_64_data].encoding_base64_UTF8StringEncoding;
}

- (NSData *)RSA_EN_Data:(NSData *)data {
    return [self secKeyCryptData:data isEn:YES];
}

- (NSData *)secKeyCryptData:(NSData *)data isEn:(BOOL)isEn {
    
    OSStatus status = noErr;
    
    size_t textLen1 = 0; // en -> cipherTextLen  de->plainTextLen
    size_t textLen2 = 0; // en -> plainTextLen   de->cipherTextLen
    
    uint8_t *uint8_tBuffer = NULL;
    SecKeyRef seckeyRef = isEn ? _publicKeyRef : _privateKeyRef;
    
    // 计算缓冲区大小
    textLen1 = SecKeyGetBlockSize(seckeyRef);
    textLen2 = data.length;
    
    NSUInteger memset_len = isEn ? textLen1: textLen2;
    // 分配缓冲区
    uint8_tBuffer = malloc(memset_len * sizeof(uint8_t));
    memset((void *)uint8_tBuffer, 0x0, memset_len);
    
    // 使用公钥加密
    status = isEn ? SecKeyEncrypt(seckeyRef,
                                  kTypeOfWrapPadding,
                                  (const uint8_t *)data.bytes,
                                  textLen2,
                                  uint8_tBuffer,
                                  &textLen1
                                  ) : SecKeyDecrypt(seckeyRef,
                                                    kTypeOfWrapPadding,
                                                    (const uint8_t *)data.bytes,
                                                    textLen1,
                                                    uint8_tBuffer,
                                                    &textLen2
                                                    );
    
    NSAssert(status == noErr, @"EN error，OSStatus == %d", status);
    NSUInteger len = isEn ? textLen1: textLen2;
    // 生成密文或明文数据
    NSData  *datas = [NSData dataWithBytes:(const void *)uint8_tBuffer length:len];
    
    if (uint8_tBuffer) free(uint8_tBuffer);
    
    return datas;
}
- (NSData *)RSA_DE_Data:(NSData *)data {
    return [self secKeyCryptData:data isEn:NO];
}

- (void)rsa_public_key_path:(NSString *)path; {
    
    NSAssert(path.length != 0, @"公钥路径为空");
    // 删除当前公钥
    if (_publicKeyRef) CFRelease(_publicKeyRef);
    
    // 从一个 DER 表示的证书创建一个证书对象
    NSData *certificateData = [NSData dataWithContentsOfFile:path];
    SecCertificateRef certificateRef = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certificateData);
    NSAssert(certificateRef != NULL, @"公钥文件错误");
    
    // 返回一个默认 X509 策略的公钥对象
    SecPolicyRef policyRef = SecPolicyCreateBasicX509();
    // 包含信任管理信息的结构体
    SecTrustRef trustRef;
    
    // 基于证书和策略创建一个信任管理对象
    OSStatus status = SecTrustCreateWithCertificates(certificateRef, policyRef, &trustRef);
    NSAssert(status == errSecSuccess, @"创建信任管理对象失败");
    [self vaildTrustRef:trustRef];
    // 评估之后返回公钥子证书
    _publicKeyRef = SecTrustCopyPublicKey(trustRef);
    NSAssert(_publicKeyRef != NULL, @"公钥创建失败");
    
    if (certificateRef) CFRelease(certificateRef);
    if (policyRef) CFRelease(policyRef);
    if (trustRef) CFRelease(trustRef);
}

// 信任结果
// 评估指定证书和策略的信任管理是否有效
//#if __IPHONE_OS_VERSION_MAX_ALLOWED > __IPHONE_10_3
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
- (void)vaildTrustRef:(SecTrustRef)trustRef {
    // 评估指定证书和策略的信任管理是否有效
    if (@available(iOS 12, macOS 10.14, tvOS 12, watchOS 5, *)) {
        CFErrorRef error;
        if (SecTrustEvaluateWithError(trustRef,&error) == NO){}
    } else {
        SecTrustResultType trustResult;
        SecTrustEvaluate(trustRef, &trustResult);
    }
}

- (void)rsa_private_key_path:(NSString *)path pwd:(NSString *)pwd {
    
    NSAssert(path.length != 0, @"私钥路径为空");
    // 删除当前私钥
    if (_privateKeyRef) CFRelease(_privateKeyRef);
    
    NSData *PKCS12Data = [NSData dataWithContentsOfFile:path];
    CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
    CFStringRef passwordRef = (__bridge CFStringRef)pwd;
    
    // 从 PKCS #12 证书中提取标示和证书
    SecIdentityRef myIdentity;
    const void *keys[] = {kSecImportExportPassphrase};
    const void *values[] = {passwordRef};
    CFDictionaryRef optionsDictionary = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    
    // 返回 PKCS #12 格式数据中的标示和证书
    OSStatus status = SecPKCS12Import(inPKCS12Data, optionsDictionary, &items);
    CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(items, 0);
    myIdentity = (SecIdentityRef)CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemIdentity);
    
    SecTrustRef trustRef;
    trustRef = (SecTrustRef)CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemTrust);
    
    if (optionsDictionary) CFRelease(optionsDictionary);
    NSAssert(status == noErr, @"提取身份和信任失败");
    
    // 评估指定证书和策略的信任管理是否有效
    [self vaildTrustRef:trustRef];
    
    // 提取私钥
    status = SecIdentityCopyPrivateKey(myIdentity, &_privateKeyRef);
    NSAssert(status == errSecSuccess, @"私钥创建失败");
    CFRelease(items);
}

- (void)createKey:(NSString *)key isPublic:(BOOL)isPublic {
    
    NSArray *list = [[key componentsSeparatedByString:@"\n"] filter:^BOOL(NSString *line) {
        return ![line hasPrefix:@"-----BEGIN"] && ![line hasPrefix:@"-----END"];
    }];
    // This will be base64 encoded, decode it.
    NSData *data = [list componentsJoinedByString:@""].base_64_data;
    data = isPublic ?  data.rsa_public_data : data.rsa_private_data;
    
    //a tag to read/write keychain storage
    NSString *tag = isPublic ? @"RSA_PubKey" : @"RSA_PrivKey";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *keyAttr = [NSMutableDictionary new];
    
    [keyAttr setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [keyAttr setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyAttr setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    
    SecItemDelete((__bridge CFDictionaryRef)keyAttr);
    
    // Add persistent version of the key to system keychain
    CFStringRef cfref = isPublic ?  kSecAttrKeyClassPublic :  kSecAttrKeyClassPrivate;
    
    [keyAttr setObject:data forKey:(__bridge id)kSecValueData];
    [keyAttr setObject:(__bridge id)cfref forKey:(__bridge id)
     kSecAttrKeyClass];
    [keyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistPeer = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)keyAttr, &persistPeer);
    if (persistPeer)
        CFRelease(persistPeer);
    
    [keyAttr removeObjectForKey:(__bridge id)kSecValueData];
    [keyAttr removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    
    [keyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [keyAttr setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    if (isPublic) {
        // 删除当前公钥
        if (_publicKeyRef) CFRelease(_publicKeyRef);
        // Now fetch the SecKeyRef version of the key
        _publicKeyRef = nil;
        status = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttr, (CFTypeRef *)&_publicKeyRef);
    } else {
        // 删除当前私钥
        if (_privateKeyRef) CFRelease(_privateKeyRef);
        // Now fetch the SecKeyRef version of the key
        _privateKeyRef = nil;
        status = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttr, (CFTypeRef *)&_privateKeyRef);
    }
}
- (void)rsa_private_key:(NSString *)key {
    [self createKey:key isPublic:NO];
}
- (void)rsa_public_key:(NSString *)key {
    [self createKey:key isPublic:YES];
}

@end
