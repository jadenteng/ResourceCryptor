//
//  ResourceCryptor.m
//  ResourceX
//
//  Created by dqdeng on 2020/4/8.
//  Copyright © 2020 Jaden. All rights reserved.
//

#import "ResourceCryptor.h"
#import <CommonCrypto/CommonCrypto.h>

// 填充模式
#define kTypeOfWrapPadding        kSecPaddingPKCS1

@interface NSData (Cryptor)
- (NSData *)CCAlgorithm:(CCAlgorithm)algorithm operation:(CCOperation)operation key:(NSString *)key iv:(NSData *)iv;
@end
@interface NSData (RSA)
@property (nonatomic,readonly,assign)NSData *rsa_public_data; //
@property (nonatomic,readonly,assign)NSData *rsa_private_data; //

@end
@interface NSString (Cryptor)
@property (nonatomic,readonly)NSData *toHexData; ////转换 IV 向量
@end
static ResourceCryptor *shareInstance = nil;
@interface ResourceCryptor() {
    SecKeyRef _rsa_public_keyRef;                             // 公钥引用
    SecKeyRef _rsa_private_keyRef;                            // 私钥引用
}

@end

@implementation ResourceCryptor

+ (instancetype)share {
    if (shareInstance == nil) {
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            shareInstance = [[ResourceCryptor alloc] init];
        });
    }
    return shareInstance;
}

#pragma mark - RSA 加密/解密算法
- (void)rsa_public_key_path:(NSString *)path; {
    
    NSAssert(path.length != 0, @"公钥路径为空");
    // 删除当前公钥
    if (_rsa_public_keyRef) CFRelease(_rsa_public_keyRef);
    
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
    
    // 信任结果
    // 评估指定证书和策略的信任管理是否有效
    //#if __IPHONE_OS_VERSION_MAX_ALLOWED > __IPHONE_10_3
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (@available(iOS 12, macOS 10.14, tvOS 12, watchOS 5, *)) {
        CFErrorRef error;
        if (SecTrustEvaluateWithError(trustRef,&error) == NO){}
    } else {
        SecTrustResultType trustResult;
        status = SecTrustEvaluate(trustRef, &trustResult);
    }
    // 评估之后返回公钥子证书
    _rsa_public_keyRef = SecTrustCopyPublicKey(trustRef);
    NSAssert(_rsa_public_keyRef != NULL, @"公钥创建失败");
    
    if (certificateRef) CFRelease(certificateRef);
    if (policyRef) CFRelease(policyRef);
    if (trustRef) CFRelease(trustRef);
}
- (void)rsa_public_key:(NSString *)key {
    
    NSRange spos = [key rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    NSRange epos = [key rangeOfString:@"-----END PUBLIC KEY-----"];
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        key = [key substringWithRange:range];
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    // This will be base64 encoded, decode it.
    NSData *data = key.base_64_data;
    data = data.rsa_public_data;
    if(!data){
        return ;
    }
    
    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PubKey";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    // Add persistent version of the key to system keychain
    [publicKey setObject:data forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)
     kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return ;
    }
    
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // 删除当前公钥
    if (_rsa_public_keyRef) CFRelease(_rsa_public_keyRef);
    // Now fetch the SecKeyRef version of the key
    _rsa_public_keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&_rsa_public_keyRef);
}

- (void)rsa_private_key_path:(NSString *)path pwd:(NSString *)pwd {
    
    NSAssert(path.length != 0, @"私钥路径为空");
    // 删除当前私钥
    if (_rsa_private_keyRef) CFRelease(_rsa_private_keyRef);
    
    NSData *PKCS12Data = [NSData dataWithContentsOfFile:path];
    CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
    CFStringRef passwordRef = (__bridge CFStringRef)pwd;
    
    // 从 PKCS #12 证书中提取标示和证书
    SecIdentityRef myIdentity;
    SecTrustRef myTrust;
    const void *keys[] = {kSecImportExportPassphrase};
    const void *values[] = {passwordRef};
    CFDictionaryRef optionsDictionary = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    
    // 返回 PKCS #12 格式数据中的标示和证书
    OSStatus status = SecPKCS12Import(inPKCS12Data, optionsDictionary, &items);
    CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(items, 0);
    myIdentity = (SecIdentityRef)CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemIdentity);
    myTrust = (SecTrustRef)CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemTrust);
    
    if (optionsDictionary) CFRelease(optionsDictionary);
    NSAssert(status == noErr, @"提取身份和信任失败");
    
    // 评估指定证书和策略的信任管理是否有效
    if (@available(iOS 12, macOS 10.14, tvOS 12, watchOS 5, *)) {
        CFErrorRef error;
        if (SecTrustEvaluateWithError(trustRef,&error) == NO){}
    } else {
        SecTrustResultType trustResult;
        status = SecTrustEvaluate(myTrust, &trustResult);
    }
    
    // 提取私钥
    status = SecIdentityCopyPrivateKey(myIdentity, &_rsa_private_keyRef);
    NSAssert(status == errSecSuccess, @"私钥创建失败");
    CFRelease(items);
}

- (void)rsa_private_key:(NSString *)key {
    NSRange spos;
    NSRange epos;
    spos = [key rangeOfString:@"-----BEGIN RSA PRIVATE KEY-----"];
    if(spos.length > 0){
        epos = [key rangeOfString:@"-----END RSA PRIVATE KEY-----"];
    }else{
        spos = [key rangeOfString:@"-----BEGIN PRIVATE KEY-----"];
        epos = [key rangeOfString:@"-----END PRIVATE KEY-----"];
    }
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        key = [key substringWithRange:range];
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    // This will be base64 encoded, decode it.
    NSData *data = key.base_64_data;
    data = data.rsa_private_data;
    if(!data){
        return;
    }
    
    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PrivKey";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *privateKey = [[NSMutableDictionary alloc] init];
    [privateKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [privateKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [privateKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)privateKey);
    
    // Add persistent version of the key to system keychain
    [privateKey setObject:data forKey:(__bridge id)kSecValueData];
    [privateKey setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)
     kSecAttrKeyClass];
    [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)privateKey, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return ;
    }
    
    [privateKey removeObjectForKey:(__bridge id)kSecValueData];
    [privateKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [privateKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // 删除当前私钥
    if (_rsa_private_keyRef) CFRelease(_rsa_private_keyRef);
    // Now fetch the SecKeyRef version of the key
    _rsa_private_keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)privateKey, (CFTypeRef *)&_rsa_private_keyRef);
    if(status != noErr){
        return ;
    }
    
}

- (NSString *)RSA_EN_String:(NSString *)string {
    return [self RSA_EN_Data:string.utf_8].base64_encoded_string;
}

- (NSString *)RSA_DE_String:(NSString *)string {
    return [self RSA_DE_Data:string.base_64_data].encoding_base64_UTF8StringEncoding;
}

- (NSData *)RSA_EN_Data:(NSData *)data {
    OSStatus sanityCheck = noErr;
    size_t cipherBufferSize = 0;
    size_t keyBufferSize = 0;
    
    NSAssert(data, @"data == nil");
    NSAssert(_rsa_public_keyRef, @"_rsa_public_keyRef == nil");
    
    NSData *cipher = nil;
    uint8_t *cipherBuffer = NULL;
    
    // 计算缓冲区大小
    cipherBufferSize = SecKeyGetBlockSize(_rsa_public_keyRef);
    keyBufferSize = data.length;
    
    if (kTypeOfWrapPadding == kSecPaddingNone) {
        NSAssert(keyBufferSize <= cipherBufferSize, @"EN too large");
    }
    
    // 分配缓冲区
    cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    memset((void *)cipherBuffer, 0x0, cipherBufferSize);
    
    // 使用公钥加密
    sanityCheck = SecKeyEncrypt(_rsa_public_keyRef,
                                kTypeOfWrapPadding,
                                (const uint8_t *)data.bytes,
                                keyBufferSize,
                                cipherBuffer,
                                &cipherBufferSize
                                );
    
    NSAssert(sanityCheck == noErr, @"EN error，OSStatus == %d", sanityCheck);
    
    // 生成密文数据
    cipher = [NSData dataWithBytes:(const void *)cipherBuffer length:(NSUInteger)cipherBufferSize];
    
    if (cipherBuffer) free(cipherBuffer);
    
    return cipher;
}

- (NSData *)RSA_DE_Data:(NSData *)data {
    OSStatus sanityCheck = noErr;
    size_t cipherBufferSize = 0;
    size_t keyBufferSize = 0;
    
    NSData *key = nil;
    uint8_t *keyBuffer = NULL;
    
    SecKeyRef privateKey = _rsa_private_keyRef;
    NSAssert(privateKey != NULL, @"_rsa_private_keyRef == nil");
    
    // 计算缓冲区大小
    cipherBufferSize = SecKeyGetBlockSize(privateKey);
    keyBufferSize = data.length;
    
    NSAssert(keyBufferSize <= cipherBufferSize, @"DE  too large");
    
    // 分配缓冲区
    keyBuffer = malloc(keyBufferSize * sizeof(uint8_t));
    memset((void *)keyBuffer, 0x0, keyBufferSize);
    
    // 使用私钥解密
    sanityCheck = SecKeyDecrypt(privateKey,
                                kTypeOfWrapPadding,
                                (const uint8_t *)data.bytes,
                                cipherBufferSize,
                                keyBuffer,
                                &keyBufferSize
                                );
    
    NSAssert1(sanityCheck == noErr, @"DE error，OSStatus == %d", sanityCheck);
    
    // 生成明文数据
    key = [NSData dataWithBytes:(const void *)keyBuffer length:(NSUInteger)keyBufferSize];
    
    if (keyBuffer) free(keyBuffer);
    
    return key;
}

@end


@implementation NSData (ResourceCryptor)

#pragma mark - DES 加密/解密
- (NSData *)DES_EN:(NSString *)key iv:(NSString *)iv {
    return [self CCAlgorithm:kCCAlgorithmDES operation:kCCEncrypt key:key iv:iv.toHexData];
}
- (NSData *)DES_DE:(NSString *)key iv:(NSString *)iv {
    return [self CCAlgorithm:kCCAlgorithmDES operation:kCCDecrypt key:key iv:iv.toHexData];
}

#pragma mark - AES 加密/解密
- (NSData *)AES_EN:(NSString *)key iv:(NSString *)iv {
    return [self CCAlgorithm:kCCAlgorithmAES operation:kCCEncrypt key:key iv:iv.toHexData];
}
- (NSData *)AES_DE:(NSString *)key iv:(NSString *)iv {
    return [self CCAlgorithm:kCCAlgorithmAES operation:kCCDecrypt key:key iv:iv.toHexData];
}

@end

@implementation NSString (ResourceCryptor)

- (NSString *)AES_EN:(NSString *)key iv:(NSString *)iv {
    return [self.utf_8 DES_EN:key iv:iv].base64_encoded_string;/// BASE 64 编码
}
- (NSString *)AES_DE:(NSString *)key iv:(NSString *)iv {
    return [self.base_64_data AES_DE:key iv:iv].encoding_base64_UTF8StringEncoding;
}
- (NSString *)DES_EN:(NSString *)key iv:(NSString *)iv {
    return [self.utf_8 DES_EN:key iv:iv].base64_encoded_string;/// BASE 64 编码
}
- (NSString *)DES_DE:(NSString *)key iv:(NSString *)iv {
    return [self.base_64_data DES_DE:key iv:iv].encoding_base64_UTF8StringEncoding; /// BASE 64 解码
}

#define CC_MD5_DIGEST_LENGTH 16
- (NSString *)MD_5 {
    const char *cString = [self UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CC_MD5(cString, (CC_LONG)strlen(cString), result);
    return [NSString stringWithFormat:@"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
            result[8], result[9], result[10], result[11], result[12], result[13], result[14], result[15]];
}

- (NSString *)SHA_256 {
    const char *s = [self cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [NSData dataWithBytes:s length:strlen(s)];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(keyData.bytes, (CC_LONG)keyData.length, digest);
    NSData *out = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    
    const unsigned *hashBytes = [out bytes];
    NSString *hash = [NSString stringWithFormat:@"%08x%08x%08x%08x%08x%08x%08x%08x",
                      ntohl(hashBytes[0]), ntohl(hashBytes[1]), ntohl(hashBytes[2]),
                      ntohl(hashBytes[3]), ntohl(hashBytes[4]), ntohl(hashBytes[5]),
                      ntohl(hashBytes[6]), ntohl(hashBytes[7])];
    return hash;
}
- (CC_SHA256Block)SHA_256_block {
    return ^(NSString *key){
        const char *cKey  = [key cStringUsingEncoding:NSASCIIStringEncoding];
        const char *cData = [self cStringUsingEncoding:NSASCIIStringEncoding];
        unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
        CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
        NSData *HMACData = [NSData dataWithBytes:cHMAC length:sizeof(cHMAC)];
        const unsigned char *buffer = (const unsigned char *)[HMACData bytes];
        NSMutableString *HMAC = [NSMutableString stringWithCapacity:HMACData.length * 2];
        for (int i = 0; i < HMACData.length; ++i){
            [HMAC appendFormat:@"%02x", buffer[i]];
        }
        return HMAC;
    };
}

@end

///加密算法
@implementation NSData (Cryptor)

#pragma mark 对称加密&解密核心方法

/// 对称加密&解密核心方法
/// @param algorithm 加密算法
/// @param operation 加密/解密操作
/// @param key 密钥字符串
/// @param iv IV 向量
- (NSData *)CCAlgorithm:(CCAlgorithm)algorithm operation:(CCOperation)operation key:(NSString *)key iv:(NSData *)iv {
    
    int keySize = (algorithm == kCCAlgorithmAES) ? kCCKeySizeAES128 : kCCKeySizeDES;
    int blockSize = (algorithm == kCCAlgorithmAES) ? kCCBlockSizeAES128: kCCBlockSizeDES;
    
    // 设置密钥
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t cKey[keySize];
    bzero(cKey, sizeof(cKey));
    [keyData getBytes:cKey length:keySize];
    
    // 设置 IV 向量
    uint8_t cIv[blockSize];
    bzero(cIv, blockSize);
    int option = kCCOptionPKCS7Padding | kCCOptionECBMode;
    if (iv) {
        [iv getBytes:cIv length:blockSize];
        option = kCCOptionPKCS7Padding;
    }
    
    // 设置输出缓冲区
    size_t bufferSize = [self length] + blockSize;
    void *buffer = malloc(bufferSize);
    
    // DE or EN
    size_t cryptorSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          algorithm,
                                          option,
                                          cKey,
                                          keySize,
                                          cIv,
                                          [self bytes],
                                          [self length],
                                          buffer,
                                          bufferSize,
                                          &cryptorSize);
    
    NSData *result = nil;
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:cryptorSize];
    } else {
        free(buffer);
        NSLog(@"[错误] 加密或解密失败 | 状态编码: %d", cryptStatus);
    }
    return result;
}

@end

@implementation  NSString (Cryptor)

//转换 IV 向量
- (NSData *)toHexData {
    NSMutableData *data = [[NSMutableData alloc] init];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    for (int i = 0; i < ([self length] / 2); i++) {
        byte_chars[0] = [self characterAtIndex:i*2];
        byte_chars[1] = [self characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    return data;
}

@end
@implementation  NSString (Conversion)

/// 转换为base_64 string
- (NSString *)base_64 {
    return self.utf_8.base64_encoded_string;
}
/// base64 转为 string
- (NSString *)encoding_base64 {
    return self.base_64_data.encoding_base64_UTF8StringEncoding;
}

/// string 转换为 base64 data
- (NSData *)base_64_data {
    return [[NSData alloc] initWithBase64EncodedString:self options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

- (NSData *)utf_8 {
    return [self dataUsingEncoding:NSUTF8StringEncoding];
}

@end

@implementation  NSData (Conversion)

///data 转换为base64字符串
- (NSString * )base64_encoded_string {
    return [self base64EncodedStringWithOptions:0];
}
/// 将data 按照 utf8 解码 为字符串
- (NSString *)encoding_base64_UTF8StringEncoding {
    return [[NSString alloc] initWithData:self encoding:NSUTF8StringEncoding];
}


@end

@implementation NSData (RSA)

//credit: http://hg.mozilla.org/services/fx-home/file/tip/Sources/NetworkAndStorage/CryptoUtils.m#l1036
- (NSData *)rsa_public_data {
    // Skip ASN.1 public key header
    if (self == nil) return(nil);
    
    unsigned long len = [self length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[self bytes];
    unsigned int  idx     = 0;
    
    if (c_key[idx++] != 0x30) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] =
    { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    if (c_key[idx++] != '\0') return(nil);
    
    // Now make a new NSData from this buffer
    return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}
//credit: http://hg.mozilla.org/services/fx-home/file/tip/Sources/NetworkAndStorage/CryptoUtils.m#l1036
- (NSData *)rsa_private_data {
    // Skip ASN.1 private key header
    if (self == nil) return(nil);
    
    unsigned long len = [self length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[self bytes];
    unsigned int  idx     = 22; //magic byte at offset 22
    
    if (0x04 != c_key[idx++]) return nil;
    
    //calculate length of the key
    unsigned int c_len = c_key[idx++];
    int det = c_len & 0x80;
    if (!det) {
        c_len = c_len & 0x7f;
    } else {
        int byteCount = c_len & 0x7f;
        if (byteCount + idx > len) {
            //rsa length field longer than buffer
            return nil;
        }
        unsigned int accum = 0;
        unsigned char *ptr = &c_key[idx];
        idx += byteCount;
        while (byteCount) {
            accum = (accum << 8) + *ptr;
            ptr++;
            byteCount--;
        }
        c_len = accum;
    }
    
    // Now make a new NSData from this buffer
    return [self subdataWithRange:NSMakeRange(idx, c_len)];
}

@end
