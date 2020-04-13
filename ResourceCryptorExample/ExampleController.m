//
//  ExampleController.m
//  ResourceCryptorExample
//
//  Created by dqdeng on 2020/4/9.
//  Copyright © 2020 Jaden. All rights reserved.
//

#import "ExampleController.h"
#import <ResourceCryptor/ResourceCryptor.h>
#import <Network/Network.h>
#import "R_SA.h"

NSString *key = @"iojyxgas+x*$a$*s";
NSString *iv = @"iojyxgas+x*$a$*s";

NSString *string = @"hello hello";

@interface PublicKeyInfo : NSObject

@property (nonatomic,strong)NSString *version; //
@property (nonatomic,strong)NSString *pem; //

@end
@implementation PublicKeyInfo

@end
@interface ExampleController ()

@end


@implementation ExampleController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
}

- (void)testRSA1 {
    
    [self test:@"RSA 1" :^{
        //1加载公钥
        NSString *path = [[NSBundle mainBundle] pathForResource:@"ca.der" ofType:nil];
        
        RSA_.add_pubPath(path);
        //2:使用公钥加密
        NSString *en_str = RSA_.EN_String(@"hello");
        NSLog(@"加密后结果:%@",en_str);
        
        //3:加载私钥,并且指定导出p12时设定的密码
        NSString *p12Path = [[NSBundle mainBundle] pathForResource:@"p.p12" ofType:nil];
        RSA_.add_privatePath(p12Path,@"123456");//path:路径 pwd:密码
        
        // 4. 使用私钥解密
        NSString *de_str = RSA_.DE_String(en_str);
        NSLog(@"解密结果 %@", de_str);
    }];
}

- (void)testRSA2 {
    
    [self test:@"RSA 2" :^{
        
        NSString *pubkey = @"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDI2bvVLVYrb4B0raZgFP60VXY\ncvRmk9q56QiTmEm9HXlSPq1zyhyPQHGti5FokYJMzNcKm0bwL1q6ioJuD4EFI56D\na+70XdRz1CjQPQE3yXrXXVvOsmq9LsdxTFWsVBTehdCmrapKZVVx6PKl7myh0cfX\nQmyveT/eqyZK1gYjvQIDAQAB\n-----END PUBLIC KEY-----";
        NSString *privkey = @"-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMMjZu9UtVitvgHS\ntpmAU/rRVdhy9GaT2rnpCJOYSb0deVI+rXPKHI9Aca2LkWiRgkzM1wqbRvAvWrqK\ngm4PgQUjnoNr7vRd1HPUKNA9ATfJetddW86yar0ux3FMVaxUFN6F0KatqkplVXHo\n8qXubKHRx9dCbK95P96rJkrWBiO9AgMBAAECgYBO1UKEdYg9pxMX0XSLVtiWf3Na\n2jX6Ksk2Sfp5BhDkIcAdhcy09nXLOZGzNqsrv30QYcCOPGTQK5FPwx0mMYVBRAdo\nOLYp7NzxW/File//169O3ZFpkZ7MF0I2oQcNGTpMCUpaY6xMmxqN22INgi8SHp3w\nVU+2bRMLDXEc/MOmAQJBAP+Sv6JdkrY+7WGuQN5O5PjsB15lOGcr4vcfz4vAQ/uy\nEGYZh6IO2Eu0lW6sw2x6uRg0c6hMiFEJcO89qlH/B10CQQDDdtGrzXWVG457vA27\nkpduDpM6BQWTX6wYV9zRlcYYMFHwAQkE0BTvIYde2il6DKGyzokgI6zQyhgtRJ1x\nL6fhAkB9NvvW4/uWeLw7CHHVuVersZBmqjb5LWJU62v3L2rfbT1lmIqAVr+YT9CK\n2fAhPPtkpYYo5d4/vd1sCY1iAQ4tAkEAm2yPrJzjMn2G/ry57rzRzKGqUChOFrGs\nlm7HF6CQtAs4HC+2jC0peDyg97th37rLmPLB9txnPl50ewpkZuwOAQJBAM/eJnFw\nF5QAcL4CYDbfBKocx82VX/pFXng50T7FODiWbbL4UnxICE0UBFInNNiWJxNEb6jL\n5xd0pcy9O2DOeso=\n-----END PRIVATE KEY-----";
        
        NSString *info_str = @"hello hello";
        // 1:加载公钥
        RSA_.add_pubKey(pubkey);
        // 2:使用公钥加密
        NSString *en_str = RSA_.EN_String(info_str);
        // 3:加载私钥
        RSA_.add_privateKey(privkey);
        // 4:使用私钥解密
        NSLog(@"解密结果 %@", RSA_.DE_String(en_str));
    }];
}

- (void)testHMAC {
    
    [self test:@"HMAC" :^{
        NSString *string = @"hello";
        
        NSLog(@"MD_5:%@",string.MD_5);
        NSLog(@"SHA_1:%@",string.SHA_1);
        NSLog(@"SHA_224:%@",string.SHA_224);
        NSLog(@"SHA_384:%@",string.SHA_384);
        NSLog(@"SHA_256:%@",string.SHA_256);
        NSLog(@"SHA_512:%@",string.SHA_512);
        
        NSLog(@"==============HMAC=======================");
        NSLog(@"MD_5:%@",string.SHA_MD5_HMAC_block(key));
        NSLog(@"SHA_256:%@",string.SHA_256_HMAC_block(key));
        NSLog(@"SHA_224:%@",@"hello".SHA_224_HMAC_block(key));
        NSLog(@"SHA_1:%@",@"hello".SHA_1_HMAC_block(key));
    }];
}
- (void)testDES {
    
    [self test:@"DES":^{
        /// jsonObj
        NSDictionary *paramters = @{@"key1":@"10",@"key2":@1};
        NSData *jsonData = paramters.json_Data_utf8;
        /// 加密DES
        NSData *en_data = jsonData.EN_DES(key,iv);
        /// 解密
        NSData *de_data = en_data.DE_DES(key, iv);
        NSDictionary *de_json = de_data.JSON_Object;
        NSLog(@"解密:%@",de_json);
        
        /// String
        NSString *en_str = string.EN_DES(key,iv);
        NSLog(@"加密en_str:%@",en_str);
        NSLog(@"解密:%@",en_str.DE_DES(key,iv));
    }];
}

- (void)testAES {
    
    [self test:@"AES":^{
        /// jsonObj
        NSDictionary *paramters = @{@"key1":@"10",@"key2":@1};
        NSData *jsonData = paramters.json_Data;
        /// 加密
        NSData *en_data = [jsonData AES_EN:key iv:iv];
        /// 解密
        NSData *de_data = [en_data AES_DE:key iv:iv];
        NSDictionary *de_json = de_data.JSON_Object;
        NSLog(@"%@",de_json);
        
        /// String
        NSString *en_str = string.EN_AES(key,iv);
        NSLog(@"加密en_str:%@",en_str);
        NSLog(@"解密:%@",en_str.DE_AES(key,iv));
        
    }];
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    switch (indexPath.row) {
        case 0:
            [self testRSA1];
            break;
        case 1:
            [self testRSA2];
            break;
        case 2:
            [self testAES];
            break;
        case 3:
            [self testDES];
            break;
        case 4:
            [self testHMAC];
            break;
        default:
            break;
    }
}

- (void)test:(NSString *)des :(dispatch_block_t)block {
    NSLog(@"\n=============== %@ ======================\n",des);
    block();
}

@end
