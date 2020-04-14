//
//  ResourceCryptor.m
//  ResourceX
//
//  Created by dqdeng on 2020/4/8.
//  Copyright © 2020 Jaden. All rights reserved.
//

#import "ResourceCryptor.h"
#import <CommonCrypto/CommonCrypto.h>

typedef BOOL (^Array_Filter_Block)(id );

@interface NSString (HMAC)
- (NSString *)cc_stringUsingAlg:(CCHmacAlgorithm)alg;
- (NSString *)cc_hmacStringUsingAlg:(CCHmacAlgorithm)alg key:(NSString *)key;
@end


@interface NSData (Cryptor)
/// 对称加密&解密核心方法
/// @param algorithm 加密算法
/// @param operation 加密/解密操作
/// @param key 密钥字符串
/// @param iv IV 向量
- (NSData *)CCAlgorithm:(CCAlgorithm)algorithm operation:(CCOperation)operation key:(NSString *)key iv:(NSString *)iv;
@end

@interface NSData (RSA)
///RSA public_data
@property (nonatomic,readonly,assign)NSData *rsa_public_data;
///RSA private_data
@property (nonatomic,readonly,assign)NSData *rsa_private_data;
@end

@interface NSArray (filter)
- (NSMutableArray *)filter:(Array_Filter_Block)predicate;
@end


@implementation NSData (ResourceCryptor)

#pragma mark - DES 加密/解密
- (CRYPTOR_BLOCK)EN_DES {
    return ^(NSString *key, NSString *iv) {
        return [self DES_EN:key iv:iv];
    };
}

- (CRYPTOR_BLOCK)DE_DES {
    return ^(NSString *key,NSString *iv) {
        return [self DES_DE:key iv:iv];
    };
}

#pragma mark - AES 加密/解密
- (CRYPTOR_BLOCK)EN_AES {
    return ^(NSString *key,NSString *iv) {
        return [self AES_EN:key iv:iv];
    };
}

- (CRYPTOR_BLOCK)DE_AES {
    return ^(NSString *key,NSString *iv) {
        return [self AES_DE:key iv:iv];
    };
}
- (id)JSON_Object {
    NSString *json =  [self.encoding_base64_UTF8StringEncoding stringByTrimmingCharactersInSet:[NSCharacterSet controlCharacterSet]];
    return [NSJSONSerialization JSONObjectWithData:json.utf_8 options:0 error:nil];
}

@end

@implementation NSString (ResourceCryptor)

#pragma mark - DES 加密/解密
- (CRYPTOR_STR_BLOCK)EN_DES {
    return ^(NSString *key, NSString *iv) {
        return [self DES_EN:key iv:iv];
    };
}

- (CRYPTOR_STR_BLOCK)DE_DES {
    return ^(NSString *key,NSString *iv) {
        return [self DES_DE:key iv:iv];
    };
}

#pragma mark - AES 加密/解密
- (CRYPTOR_STR_BLOCK)EN_AES {
    return ^(NSString *key,NSString *iv) {
        return [self AES_EN:key iv:iv];
    };
}

- (CRYPTOR_STR_BLOCK)DE_AES {
    return ^(NSString *key,NSString *iv) {
        return [self AES_DE:key iv:iv];
    };
}

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

//- (NSString *)md_5 {
//    return [self cc_stringUsingAlg:kCCHmacAlgMD5];
//}
- (NSString *)SHA_1{
    return [self cc_stringUsingAlg:kCCHmacAlgSHA1];
}
/// 常用方式 尽量减少内存开辟空间
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
- (NSString *)SHA_384{
    return [self cc_stringUsingAlg:kCCHmacAlgSHA384];
}
- (NSString *)SHA_512{
    return [self cc_stringUsingAlg:kCCHmacAlgSHA512];
}
- (NSString *)SHA_224 {
    return [self cc_stringUsingAlg:kCCHmacAlgSHA224];
}
- (k_CCHmacAlgSHA_block)SHA_256_HMAC_block {
    return ^(NSString *key){
        return [self cc_hmacStringUsingAlg:kCCHmacAlgSHA256 key:key];
    };
}
- (k_CCHmacAlgSHA_block)SHA_MD5_HMAC_block {
    return ^(NSString *key){
        return [self cc_hmacStringUsingAlg:kCCHmacAlgMD5 key:key];
    };
}
- (k_CCHmacAlgSHA_block)SHA_1_HMAC_block {
    return ^(NSString *key){
        return [self cc_hmacStringUsingAlg:kCCHmacAlgSHA1 key:key];
    };
}
- (k_CCHmacAlgSHA_block)SHA_384_HMAC_block {
    return ^(NSString *key){
        return [self cc_hmacStringUsingAlg:kCCHmacAlgSHA384 key:key];
    };
}
- (k_CCHmacAlgSHA_block)SHA_512_HMAC_block {
    return ^(NSString *key){
        return [self cc_hmacStringUsingAlg:kCCHmacAlgSHA512 key:key];
    };
}
- (k_CCHmacAlgSHA_block)SHA_224_HMAC_block {
    return ^(NSString *key){
        return [self cc_hmacStringUsingAlg:kCCHmacAlgSHA224 key:key];
    };
}

@end

#pragma mark - HMAC
@implementation NSString (HMAC)

- (NSString *)cc_stringUsingAlg:(CCHmacAlgorithm)alg {
    const char *cstr = [self cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:self.length];
    
    size_t size;
    switch (alg) {
        case kCCHmacAlgMD5: size = CC_MD5_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA1: size = CC_SHA1_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA224: size = CC_SHA224_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA256: size = CC_SHA256_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA384: size = CC_SHA384_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA512: size = CC_SHA512_DIGEST_LENGTH; break;
        default: return nil;
    }
    uint8_t digest[size];
    switch (alg) {
        case kCCHmacAlgSHA1:CC_SHA1(data.bytes, (CC_LONG)data.length, digest);break;
        case kCCHmacAlgMD5:CC_MD5(data.bytes, (CC_LONG)data.length, digest);break;
        case kCCHmacAlgSHA256:CC_SHA256(data.bytes, (CC_LONG)data.length, digest);break;
        case kCCHmacAlgSHA384:CC_SHA384(data.bytes, (CC_LONG)data.length, digest);break;
        case kCCHmacAlgSHA512:CC_SHA512(data.bytes, (CC_LONG)data.length, digest);break;
        case kCCHmacAlgSHA224:CC_SHA224(data.bytes, (CC_LONG)data.length, digest);break;
        default:
            NSAssert(nil, @"未配置加密方式");
            break;
    }
    
    NSMutableString *output = [NSMutableString stringWithCapacity:size * 2];
    for(int i = 0; i < size; i++)
        [output appendFormat:@"%02x", digest[i]];
    
    return output;
}

- (NSString *)cc_hmacStringUsingAlg:(CCHmacAlgorithm)alg key:(NSString *)key {
    
    const char *cKey  = [key cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [self cStringUsingEncoding:NSASCIIStringEncoding];
    size_t size;
    switch (alg) {
        case kCCHmacAlgMD5: size = CC_MD5_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA1: size = CC_SHA1_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA224: size = CC_SHA224_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA256: size = CC_SHA256_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA384: size = CC_SHA384_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA512: size = CC_SHA512_DIGEST_LENGTH; break;
        default: return nil;
    }
    unsigned char cHMAC[size];
    CCHmac(alg, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    NSData *HMACData = [NSData dataWithBytes:cHMAC length:sizeof(cHMAC)];
    const unsigned char *buffer = (const unsigned char *)[HMACData bytes];
    NSMutableString *HMAC = [NSMutableString stringWithCapacity:HMACData.length * 2];
    for (int i = 0; i < HMACData.length; ++i){
        [HMAC appendFormat:@"%02x", buffer[i]];
    }
    return HMAC;
}


@end

#pragma mark - Cryptor
///加密算法
@implementation NSData (Cryptor)

/// 对称加密&解密核心方法
- (NSData *)CCAlgorithm:(CCAlgorithm)algorithm operation:(CCOperation)operation key:(NSString *)key iv:(NSString *)iv {
   
    int keySize = (algorithm == kCCAlgorithmAES) ? kCCKeySizeAES128 : kCCKeySizeDES;
    int blockSize = (algorithm == kCCAlgorithmAES) ? kCCBlockSizeAES128: kCCBlockSizeDES;
    
    NSUInteger dataLength  = self.length;
    
    // 设置密钥
    char keyPtr[keySize + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
   
    // 设置 IV 向量
    char ivPtr[blockSize + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    /**
    kCCOptionPKCS7Padding                      CBC 的加密
    kCCOptionPKCS7Padding | kCCOptionECBMode   ECB 的加密
    */
    int option = kCCOptionPKCS7Padding | kCCOptionECBMode;
    if (iv) {
        option = kCCOptionPKCS7Padding;
    }
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    // 设置输出缓冲区
    size_t bufferSize = dataLength + blockSize;
    void *buffer = malloc(bufferSize);
    
    //开始加密
    size_t numBytesCrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt( operation,
                                          algorithm,
                                          option,
                                          keyPtr,
                                          keySize,
                                          ivPtr /* initialization vector (optional) */,
                                          [self bytes],
                                          dataLength, /* input */
                                          buffer,
                                          bufferSize, /* output */
                                          &numBytesCrypted );
    
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
    }
    free(buffer);
    return nil;
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

#pragma mark - Conversion  (NSString NSData)
@implementation  NSString (Conversion)

/// string to base64 string
- (NSString *)base_64 {
    return self.utf_8.base64_encoded_string;
}
/// base64 转为 string
- (NSString *)encoding_base64 {
    return self.base_64_data.encoding_base64_UTF8StringEncoding;
}

/// base64string 转换为 base64 data
- (NSData *)base_64_data {
    return [[NSData alloc] initWithBase64EncodedString:self options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

- (NSData *)utf_8 {
    return [self dataUsingEncoding:NSUTF8StringEncoding];
}

- (NSData *)rsa_data {
    
    NSArray *list = [[self componentsSeparatedByString:@"\n"] filter:^BOOL(NSString *line) {
        return ![line hasPrefix:@"-----BEGIN"] && ![line hasPrefix:@"-----END"];
    }];
    // This will be base64 encoded, decode it.
    NSData *data = [list componentsJoinedByString:@""].base_64_data;
    return data;
}
- (id)JSON_Object {
    NSString *json = [self stringByTrimmingCharactersInSet:[NSCharacterSet controlCharacterSet]];
    NSError *err;
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:json.utf_8 options:0 error:&err];
    if(err) {
        NSLog(@"json解析失败：%@",err);
        return nil;
    }
    return dic;
}

@end


@implementation  NSData (Conversion)

///base64data 转为 base64 string
- (NSString * )base64_encoded_string {
    return [self base64EncodedStringWithOptions:0];
}
///// base64data 转为 base64 string
//- (NSString *)base64_string {
//     return [self base64EncodedStringWithOptions:0].base_64;
//}
/// base64data 转为 data
- (NSData *)base64_encoded_data {
    return [self base64EncodedDataWithOptions:NSDataBase64Encoding64CharacterLineLength];
}
/// 将data 按照 utf8 解码 为字符串
- (NSString *)encoding_base64_UTF8StringEncoding {
    return [[NSString alloc] initWithData:self encoding:NSUTF8StringEncoding];
}
/// data to base64 data
- (NSData *)base64_data {
    return self.encoding_base64_UTF8StringEncoding.utf_8;
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

@implementation NSString (Private)


- (NSString *)AES_EN:(NSString *)key iv:(NSString *)iv {
    return [self.utf_8 AES_EN:key iv:iv].base64_encoded_string;/// BASE 64 string 编码
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
@end

@implementation NSData (Private)

- (NSData *)DES_EN:(NSString *)key iv:(NSString *)iv {
    return [self CCAlgorithm:kCCAlgorithmDES operation:kCCEncrypt key:key iv:iv];
}
- (NSData *)DES_DE:(NSString *)key iv:(NSString *)iv {
    return [self CCAlgorithm:kCCAlgorithmDES operation:kCCDecrypt key:key iv:iv];
}


- (NSData *)AES_EN:(NSString *)key iv:(NSString *)iv {
    return [self CCAlgorithm:kCCAlgorithmAES operation:kCCEncrypt key:key iv:iv];
}
- (NSData *)AES_DE:(NSString *)key iv:(NSString *)iv {
    return [self CCAlgorithm:kCCAlgorithmAES operation:kCCDecrypt key:key iv:iv];
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

@implementation NSDictionary (Conversion)

- (NSData *)json_Data {
    return [NSJSONSerialization dataWithJSONObject:self options:NSJSONWritingPrettyPrinted error:nil];
}
- (NSData *)json_Data_utf8 {
    return self.json_String.base_64.base_64_data;
}
- (NSString *)json_String {
    NSMutableString *json_str = [[NSMutableString alloc] initWithString:[[NSString alloc] initWithData:self.json_Data encoding:NSUTF8StringEncoding]];
    //去除空格
    return [json_str stringByReplacingOccurrencesOfString:@"\\" withString:@""];
}
@end
