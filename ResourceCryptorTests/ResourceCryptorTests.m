//
//  ResourceCryptorTests.m
//  ResourceCryptorTests
//
//  Created by dqdeng on 2020/4/9.
//  Copyright © 2020 Jaden. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <ResourceCryptor/ResourceCryptor.h>
#import <ResourceCryptor/R_SA.h>

NSString *key = @"iojyxgas+x*$a$*s";
NSString *iv = @"iojyxgas+x*$a$*s";

NSString *HELLO = @"hello";
@interface ResourceCryptorTests : XCTestCase

@end

@implementation ResourceCryptorTests

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}
- (void)testMD5 {
    NSString *en = @"hello".MD_5;
    XCTAssertNotNil(en);
    XCTAssertEqualObjects(en, @"5d41402abc4b2a76b9719d911017c592");
}

- (void)testSHA1 {
    NSString *en = @"hello".SHA_1;
    XCTAssertNotNil(en);
    XCTAssertEqualObjects(en, @"aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
}
- (void)testSHA224 {
    NSString *en = @"hello".SHA_224;
    XCTAssertNotNil(en);
    XCTAssertEqualObjects(en, @"ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193");
}
- (void)testSHA256 {
    NSString *en = @"hello".SHA_256;
    XCTAssertNotNil(en);
    XCTAssertEqualObjects(en, @"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}
- (void)testSHA384 {
    NSString *en = @"hello".SHA_384;
    XCTAssertNotNil(en);
    XCTAssertEqualObjects(en, @"59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f");
}
- (void)testSHA512 {
    NSString *en = @"hello".SHA_512;
    XCTAssertNotNil(en);
    XCTAssertEqualObjects(en, @"9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043");
}

- (void)testSHA_256_HMAC_block {
   
    NSString *en =  HELLO.SHA_256_HMAC_block(key);
    XCTAssertNotNil(en);
    XCTAssertEqualObjects(en,@"6221287c85a28396a510af1164543d699eef3df12471f2960058f57c2ca3992c");
}
- (void)testSHA_MD5_HMAC_block {
    NSString *en =  HELLO.SHA_MD5_HMAC_block(key);
    XCTAssertNotNil(en);
    XCTAssertEqualObjects(en,@"1b240f8d50bfca5753392cad7e2244af");
}
- (void)testSHA_1_HMAC_block {
    NSString *en =  HELLO.SHA_1_HMAC_block(key);
    XCTAssertNotNil(en);
    XCTAssertEqualObjects(en,@"54d983d68e986b4af170e6ca3244cd328f8aeacd");
}
- (void)testSHA_224_HMAC_block {
    NSString *en =  @"kelp".SHA_224_HMAC_block(@"key");
    XCTAssertNotNil(en);
XCTAssertEqualObjects(en,@"4777556ee573705fcf6194de22947e09562653a84684c4b015a91e0c");
}
- (void)testSHA_384_HMAC_block {
    NSString *en =  @"kelp".SHA_384_HMAC_block(@"key");
    XCTAssertNotNil(en);
XCTAssertEqualObjects(en,@"99f2a12918f5e0c7e21ef4759ecb8dd882c95af32a204ac83928aa413e1d8e9ed312c29c41e2f3c00a78d448df11d15e");
}
- (void)testSHA_512_HMAC_block {
    NSString *en =  HELLO.SHA_512_HMAC_block(key);
    XCTAssertNotNil(en);
    XCTAssertEqualObjects(en,@"ab530e3e076ebf5ce325096b7ad91573c23adfa08e0f222f2b550abfb135fa498e956353c0a2b404d1ebacdddab577aad8fe8f14d39271196f1b90c44710bd47");
}

- (void)testAES_String {
    
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
    NSString *str = @"hello";
    NSString *en = str.EN_AES(key, iv);
    NSString *de = en.DE_AES(key,iv);
    XCTAssertNotNil(de);
    XCTAssertEqualObjects(str, de);
}


- (void)testDES_String {
    
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
    NSString *str = @"hello";
    NSString *en = str.EN_DES(key, iv);
    NSString *de = en.DE_DES(key,iv);
    XCTAssertNotNil(en);
    XCTAssertEqualObjects(str, de);
}

- (void)testDES_DATA {
    
    NSDictionary *paramters = @{@"key1":@"10",@"key2":@1};
    NSData *jsonData = paramters.json_Data;
    NSData *en_data = jsonData.EN_DES(key,iv);
    /// 解密
    NSData *de_data = en_data.DE_DES(key, iv);
    NSDictionary *json = de_data.JSON_Object;
    
    XCTAssertNotNil(jsonData);
    XCTAssertNotNil(en_data);
    XCTAssertEqualObjects(paramters, json);
}

- (void)testAES_DATA {
    
    NSDictionary *paramters = @{@"key1":@"10",@"key2":@1};
    NSData *jsonData = paramters.json_Data;
    NSData *en_data = jsonData.EN_AES(key,iv);
    /// 解密
    NSData *de_data = en_data.DE_AES(key, iv);
    NSDictionary *json = de_data.JSON_Object;
    
    XCTAssertNotNil(jsonData);
    XCTAssertNotNil(en_data);
    XCTAssertEqualObjects(paramters, json);
}

- (void)testbase_64 {
    NSString *en = @"acc".base_64;
    XCTAssertNotNil(en);
}

- (void)testencoding_base64{
    NSString *en = @"acc".base_64.encoding_base64;
    XCTAssertNotNil(en);
}
- (void)testbase_64_data {
    NSString *base64 = @"acc".base_64;
    NSData *en = base64.base_64_data;
    XCTAssertNotNil(en);
}
- (void)testutf_8{
    NSData *en = @"acc".utf_8;
    XCTAssertNotNil(en);
}
- (void)testbase64_encoded_string {
    NSString *en = @"acc".base_64.base_64_data.base64_encoded_string;
    XCTAssertNotNil(en);
}
- (void)testencoding_base64_UTF8StringEncoding {
    NSString *en = @"acc".utf_8.encoding_base64_UTF8StringEncoding;
       XCTAssertNotNil(en);
}
- (void)testjson_Data {
    NSData *en = @{}.json_Data;
    XCTAssertNotNil(en);
}
- (void)testdatajson_Data {
    NSData *en = @{}.json_Data.JSON_Object;
    XCTAssertNotNil(en);
}

- (void)testRSA {
    NSString *pubkey = @"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDI2bvVLVYrb4B0raZgFP60VXY\ncvRmk9q56QiTmEm9HXlSPq1zyhyPQHGti5FokYJMzNcKm0bwL1q6ioJuD4EFI56D\na+70XdRz1CjQPQE3yXrXXVvOsmq9LsdxTFWsVBTehdCmrapKZVVx6PKl7myh0cfX\nQmyveT/eqyZK1gYjvQIDAQAB\n-----END PUBLIC KEY-----";
     NSString *privkey = @"-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMMjZu9UtVitvgHS\ntpmAU/rRVdhy9GaT2rnpCJOYSb0deVI+rXPKHI9Aca2LkWiRgkzM1wqbRvAvWrqK\ngm4PgQUjnoNr7vRd1HPUKNA9ATfJetddW86yar0ux3FMVaxUFN6F0KatqkplVXHo\n8qXubKHRx9dCbK95P96rJkrWBiO9AgMBAAECgYBO1UKEdYg9pxMX0XSLVtiWf3Na\n2jX6Ksk2Sfp5BhDkIcAdhcy09nXLOZGzNqsrv30QYcCOPGTQK5FPwx0mMYVBRAdo\nOLYp7NzxW/File//169O3ZFpkZ7MF0I2oQcNGTpMCUpaY6xMmxqN22INgi8SHp3w\nVU+2bRMLDXEc/MOmAQJBAP+Sv6JdkrY+7WGuQN5O5PjsB15lOGcr4vcfz4vAQ/uy\nEGYZh6IO2Eu0lW6sw2x6uRg0c6hMiFEJcO89qlH/B10CQQDDdtGrzXWVG457vA27\nkpduDpM6BQWTX6wYV9zRlcYYMFHwAQkE0BTvIYde2il6DKGyzokgI6zQyhgtRJ1x\nL6fhAkB9NvvW4/uWeLw7CHHVuVersZBmqjb5LWJU62v3L2rfbT1lmIqAVr+YT9CK\n2fAhPPtkpYYo5d4/vd1sCY1iAQ4tAkEAm2yPrJzjMn2G/ry57rzRzKGqUChOFrGs\nlm7HF6CQtAs4HC+2jC0peDyg97th37rLmPLB9txnPl50ewpkZuwOAQJBAM/eJnFw\nF5QAcL4CYDbfBKocx82VX/pFXng50T7FODiWbbL4UnxICE0UBFInNNiWJxNEb6jL\n5xd0pcy9O2DOeso=\n-----END PRIVATE KEY-----";
    
    NSString *info_str = @"hello hello";
    // 1:加载公钥
    RSA_.add_public_key(pubkey);
    // 2:使用公钥加密
    NSString *en_str = RSA_.EN_String(info_str);
    // 3:加载私钥
    RSA_.add_private_key(privkey);
    // 4:使用私钥解密
    NSString *DE = RSA_.DE_String(en_str);
    XCTAssertNotNil(en_str);
    XCTAssertNotNil(DE);
    
    XCTAssertEqualObjects(info_str, DE);
}

- (void)testRSA_DATA {
    
    NSString *pubkey = @"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDI2bvVLVYrb4B0raZgFP60VXY\ncvRmk9q56QiTmEm9HXlSPq1zyhyPQHGti5FokYJMzNcKm0bwL1q6ioJuD4EFI56D\na+70XdRz1CjQPQE3yXrXXVvOsmq9LsdxTFWsVBTehdCmrapKZVVx6PKl7myh0cfX\nQmyveT/eqyZK1gYjvQIDAQAB\n-----END PUBLIC KEY-----";
    NSString *privkey = @"-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMMjZu9UtVitvgHS\ntpmAU/rRVdhy9GaT2rnpCJOYSb0deVI+rXPKHI9Aca2LkWiRgkzM1wqbRvAvWrqK\ngm4PgQUjnoNr7vRd1HPUKNA9ATfJetddW86yar0ux3FMVaxUFN6F0KatqkplVXHo\n8qXubKHRx9dCbK95P96rJkrWBiO9AgMBAAECgYBO1UKEdYg9pxMX0XSLVtiWf3Na\n2jX6Ksk2Sfp5BhDkIcAdhcy09nXLOZGzNqsrv30QYcCOPGTQK5FPwx0mMYVBRAdo\nOLYp7NzxW/File//169O3ZFpkZ7MF0I2oQcNGTpMCUpaY6xMmxqN22INgi8SHp3w\nVU+2bRMLDXEc/MOmAQJBAP+Sv6JdkrY+7WGuQN5O5PjsB15lOGcr4vcfz4vAQ/uy\nEGYZh6IO2Eu0lW6sw2x6uRg0c6hMiFEJcO89qlH/B10CQQDDdtGrzXWVG457vA27\nkpduDpM6BQWTX6wYV9zRlcYYMFHwAQkE0BTvIYde2il6DKGyzokgI6zQyhgtRJ1x\nL6fhAkB9NvvW4/uWeLw7CHHVuVersZBmqjb5LWJU62v3L2rfbT1lmIqAVr+YT9CK\n2fAhPPtkpYYo5d4/vd1sCY1iAQ4tAkEAm2yPrJzjMn2G/ry57rzRzKGqUChOFrGs\nlm7HF6CQtAs4HC+2jC0peDyg97th37rLmPLB9txnPl50ewpkZuwOAQJBAM/eJnFw\nF5QAcL4CYDbfBKocx82VX/pFXng50T7FODiWbbL4UnxICE0UBFInNNiWJxNEb6jL\n5xd0pcy9O2DOeso=\n-----END PRIVATE KEY-----";
    
    NSDictionary *info_dic = @{@"key":@"num1"};
    NSData *data = info_dic.json_Data;
    // 1:加载公钥
    RSA_.add_public_key(pubkey);
    // 2:使用公钥加密
    NSData *en_data = RSA_.EN_Data(data);
    // 3:加载私钥
    RSA_.add_private_key(privkey);
    // 4:使用私钥解密
    NSData *DE = RSA_.DE_Data(en_data);
    NSDictionary *json = DE.JSON_Object;
    XCTAssertNotNil(data);
    XCTAssertNotNil(en_data);
    XCTAssertNotNil(DE);
    XCTAssertNotNil(json);
    
    XCTAssertEqualObjects(json, info_dic);

}

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}



@end
