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

//普遍的加密方法：
///客户端用RSA的公钥 加密AES的秘钥，
///服务器端用私钥解开获得的AES的秘钥，客户端再与服务器端进行AES加密的数据传输，即HTTPS协议传输的原理

- (IBAction)touchUpAction:(id)sender {
    
    PublicKeyInfo *pub = [[PublicKeyInfo alloc] init];
    pub.version = @"1.0";
    pub.pem = @"123456jkkkhhh"; //这里的值是服务器返回的 key
    
    NSString *key = @"iojyxgas+x*$a$*s";
    NSString *iv = @"iojyxgas+x*$a$*s";
    
    NSString *string = @"hello hello";
    
    [self test:@"RSA 加解密1" :^{
        
        ResourceCryptor *cry = [ResourceCryptor share];
        //1加载公钥
        [cry rsa_public_key_path:[[NSBundle mainBundle] pathForResource:@"rsacert.der" ofType:nil]];
        //2:使用公钥加密
        NSString *en_str = [cry RSA_EN_String:pub.pem];
        NSLog(@"加密后结果:%@",en_str);
        
        //3:加载私钥,并且指定导出p12时设定的密码
        [cry rsa_private_key_path:[[NSBundle mainBundle] pathForResource:@"p.p12" ofType:nil] pwd:@"123456"];
        
        // 4. 使用私钥解密
        NSLog(@"解密结果 %@", [cry RSA_DE_String:en_str]);
    }];
    
    [self test:@"RSA 加解密2" :^{
        
        NSString *pubkey = @"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDI2bvVLVYrb4B0raZgFP60VXY\ncvRmk9q56QiTmEm9HXlSPq1zyhyPQHGti5FokYJMzNcKm0bwL1q6ioJuD4EFI56D\na+70XdRz1CjQPQE3yXrXXVvOsmq9LsdxTFWsVBTehdCmrapKZVVx6PKl7myh0cfX\nQmyveT/eqyZK1gYjvQIDAQAB\n-----END PUBLIC KEY-----";
        NSString *privkey = @"-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMMjZu9UtVitvgHS\ntpmAU/rRVdhy9GaT2rnpCJOYSb0deVI+rXPKHI9Aca2LkWiRgkzM1wqbRvAvWrqK\ngm4PgQUjnoNr7vRd1HPUKNA9ATfJetddW86yar0ux3FMVaxUFN6F0KatqkplVXHo\n8qXubKHRx9dCbK95P96rJkrWBiO9AgMBAAECgYBO1UKEdYg9pxMX0XSLVtiWf3Na\n2jX6Ksk2Sfp5BhDkIcAdhcy09nXLOZGzNqsrv30QYcCOPGTQK5FPwx0mMYVBRAdo\nOLYp7NzxW/File//169O3ZFpkZ7MF0I2oQcNGTpMCUpaY6xMmxqN22INgi8SHp3w\nVU+2bRMLDXEc/MOmAQJBAP+Sv6JdkrY+7WGuQN5O5PjsB15lOGcr4vcfz4vAQ/uy\nEGYZh6IO2Eu0lW6sw2x6uRg0c6hMiFEJcO89qlH/B10CQQDDdtGrzXWVG457vA27\nkpduDpM6BQWTX6wYV9zRlcYYMFHwAQkE0BTvIYde2il6DKGyzokgI6zQyhgtRJ1x\nL6fhAkB9NvvW4/uWeLw7CHHVuVersZBmqjb5LWJU62v3L2rfbT1lmIqAVr+YT9CK\n2fAhPPtkpYYo5d4/vd1sCY1iAQ4tAkEAm2yPrJzjMn2G/ry57rzRzKGqUChOFrGs\nlm7HF6CQtAs4HC+2jC0peDyg97th37rLmPLB9txnPl50ewpkZuwOAQJBAM/eJnFw\nF5QAcL4CYDbfBKocx82VX/pFXng50T7FODiWbbL4UnxICE0UBFInNNiWJxNEb6jL\n5xd0pcy9O2DOeso=\n-----END PRIVATE KEY-----";
        
        ResourceCryptor *cry = [ResourceCryptor share];
        //1加载公钥
        [cry rsa_public_key:pubkey];
        
        //2:使用公钥加密
        NSString *en_str = [cry RSA_EN_String:pub.pem];
        NSLog(@"加密后结果:%@",en_str);
        
        //3:加载私钥
        [cry rsa_private_key:privkey];
        
        // 4. 使用私钥解密
        NSLog(@"解密结果 %@", [cry RSA_DE_String:en_str]);
    }];
    
    [self test:@"DES 加解密":^{
        NSDictionary *paramters = @{@"key1":@"10",@"key2":@1};
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:paramters options:NSJSONWritingPrettyPrinted error:nil];
        
        NSData *en_data = [jsonData DES_EN:key iv:iv];
        /// 解密
        NSData *de_data = [en_data DES_DE:key iv:iv];
        
        NSDictionary *de_json = [NSJSONSerialization JSONObjectWithData:de_data options:0 error:nil];
        NSLog(@"解密:%@",de_json);
        
        NSString *en_str = [string DES_EN:key iv:iv];
        NSLog(@"en_str:%@",en_str);
        
        NSLog(@"解密:%@",[en_str DES_DE:key iv:iv]);
    }];
    
    [self test:@"AES 加解密":^{
        
        NSDictionary *paramters = @{@"key1":@"10",@"key2":@1};
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:paramters options:NSJSONWritingPrettyPrinted error:nil];
        
        NSData *en_data = [jsonData AES_EN:key iv:iv];
        /// 解密
        NSData *de_data = [en_data AES_DE:key iv:iv];
        
        NSDictionary *de_json = [NSJSONSerialization JSONObjectWithData:de_data options:0 error:nil];
        NSLog(@"%@",de_json);
        
    }];
    
    [self test:@"MD5 AND BASE64" :^{
        
        NSString *base64 = @"ha ha ha".base_64;
        NSLog(@"base64:%@",base64);
        NSLog(@"原字符串:%@",base64.encoding_base64);
        NSLog(@"MD_5:%@",@"this  is md5".MD_5);
        NSLog(@"SHA_256:%@",@"this  is md5".SHA_256);
        NSLog(@"md:%@",@"this  is md5".SHA_256_block(@"my"));
        
    }];
    
}

- (void)test:(NSString *)des :(dispatch_block_t)block {
    NSLog(@"\n=============== %@ ======================\n",des);
    block();
}
/*
 #pragma mark - Navigation
 
 // In a storyboard-based application, you will often want to do a little preparation before navigation
 - (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
 // Get the new view controller using [segue destinationViewController].
 // Pass the selected object to the new view controller.
 }
 */

@end
