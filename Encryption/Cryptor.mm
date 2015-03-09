//
//  Cryptor.m
//  Encryption
//
//  Created by Mani on 14.12.14.
//  Copyright (c) 2014 Mani. All rights reserved.
//

#import "Cryptor.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/base64.h"
#include <string>
#include <tuple>

template<typename T>
std::tuple<bool, std::string> encode(std::string src, std::string key, std::string iv)
{
    using namespace CryptoPP;
    
    try {
        std::string dest;
        if(iv.length())
        {
            typename T::Encryption e((const byte *)key.c_str(), key.length(), (const byte *)iv.c_str());
            StringSource(src, true, new StreamTransformationFilter(e, new StringSink(dest)));
        }
        else
        {
            typename T::Encryption e((const byte *)key.c_str(), key.length());
            StringSource(src, true, new StreamTransformationFilter(e, new StringSink(dest)));
        }
        
        return std::make_tuple(true, dest);
    }
    catch(const std::exception& e)
    {
        NSLog(@"%s: %s", __FUNCTION__, e.what());
    }
    catch (...) {
        
    }
    
    return std::make_tuple<bool, std::string>(false, { });
}

template<typename T>
std::tuple<bool, std::string> decode(std::string src, std::string key, std::string iv)
{
    using namespace CryptoPP;
    
    try {
        std::string dest;
        if(iv.length())
        {
            typename T::Decryption e((const byte *)key.c_str(), key.length(), (const byte *)iv.c_str());
            StringSource(src, true, new StreamTransformationFilter(e, new StringSink(dest)));
        }
        else
        {
            typename T::Decryption e((const byte *)key.c_str(), key.length());
            StringSource(src, true, new StreamTransformationFilter(e, new StringSink(dest)));
        }
        
        return std::make_tuple(true, dest);
    }
    catch(const std::exception& e)
    {
        NSLog(@"%s: %s", __FUNCTION__, e.what());
    }
    catch (...) {
        
    }
    
    return std::make_tuple<bool, std::string>(false, { });
}


@implementation Cryptor

+(NSString *)hex_encode:(NSData *)data
{
    return [Cryptor hex_encode:data useUpperCase:NO withGroupSize:0 withGroupDelimiter:@""];
}

+(NSString *)hex_encode:(NSData *)data useUpperCase:(BOOL)upperCase
{
    return [Cryptor hex_encode:data useUpperCase:upperCase withGroupSize:0 withGroupDelimiter:@""];
}

+(NSString *)hex_encode:(NSData *)data useUpperCase:(BOOL)upperCase withGroupSize:(int)groupSize withGroupDelimiter:(NSString *)groupDelimiter
{
    using namespace CryptoPP;
    
    std::string src((const char *)data.bytes, data.length), dest;
    
    StringSource(src, true, new HexEncoder(new StringSink(dest), upperCase, groupSize, groupDelimiter.UTF8String));
    
    return [NSString stringWithCString:dest.c_str() encoding:NSUTF8StringEncoding];
}

+(NSData *)hex_decode:(NSString *)data
{
    using namespace CryptoPP;
    
    std::string src((const char *)data.UTF8String), dest;
    
    StringSource(src, true, new HexDecoder(new StringSink(dest)));
    
    return [NSData dataWithBytes:dest.c_str() length:dest.length()];
}

+(NSString *)base64_encode:(NSData *)data
{
    return [Cryptor base64_encode:data insertLineBreaks:YES maxLineLength:72];
}

+(NSString *)base64_encode:(NSData *)data insertLineBreaks:(BOOL)lineBreaks
{
    return [Cryptor base64_encode:data insertLineBreaks:lineBreaks maxLineLength:72];
}

+(NSString *)base64_encode:(NSData *)data insertLineBreaks:(BOOL)lineBreaks maxLineLength:(int)lineLength
{
    using namespace CryptoPP;
    
    std::string src((const char *)data.bytes, data.length), dest;
    
    StringSource(src, true, new Base64Encoder(new StringSink(dest), lineBreaks, lineLength));
    
    return [NSString stringWithCString:dest.c_str() encoding:NSUTF8StringEncoding];
}

+(NSData *)base64_decode:(NSString *)data
{
    using namespace CryptoPP;
        
    std::string src((const char *)data.UTF8String), dest;
        
    StringSource(src, true, new Base64Decoder(new StringSink(dest)));
        
    return [NSData dataWithBytes:dest.c_str() length:dest.length()];
    
}

#define ENCODE_AND_CONVERT_NSDATA(ALG)  { auto p = encode<ALG>(szData, szKey, szIv); \
                                        if(std::get<0>(p)) \
                                            encoded = [NSData dataWithBytes:std::get<1>(p).c_str() length:std::get<1>(p).length()]; }

#define DECODE_AND_CONVERT_NSDATA(ALG)  { auto p = decode<ALG>(szData, szKey, szIv); \
                                        if(std::get<0>(p)) \
                                            decoded = [NSData dataWithBytes:std::get<1>(p).c_str() length:std::get<1>(p).length()]; }

+(NSData *)encode:(NSString *)algorithm withKey:(NSData *)key withData:(NSData *)data withIV:(NSData *)iv
{
    using namespace CryptoPP;
    
    std::string szAlgorithm(algorithm.UTF8String);
    std::string szKey((const char *)key.bytes, key.length);
    std::string szData((const char *)data.bytes, data.length);
    std::string szIv;
    if(iv != nil)
        szIv = std::string((const char *)iv.bytes, iv.length);
    
    NSData *encoded = nil;
    
    if(szAlgorithm == "aes_ecb")
        ENCODE_AND_CONVERT_NSDATA(ECB_Mode<AES>)
        
    if(szAlgorithm == "aes_cbc")
        ENCODE_AND_CONVERT_NSDATA(CBC_Mode<AES>)

    if(szAlgorithm == "aes_cfb")
        ENCODE_AND_CONVERT_NSDATA(CFB_Mode<AES>)

    if(szAlgorithm == "aes_ofb")
        ENCODE_AND_CONVERT_NSDATA(OFB_Mode<AES>)

    
    return encoded;
}

+(NSData *)decode:(NSString *)algorithm withKey:(NSData *)key withData:(NSData *)data withIV:(NSData *)iv
{
    using namespace CryptoPP;
    
    std::string szAlgorithm(algorithm.UTF8String);
    std::string szKey((const char *)key.bytes, key.length);
    std::string szData((const char *)data.bytes, data.length);
    std::string szIv;
    if(iv != nil)
        szIv = std::string((const char *)iv.bytes, iv.length);
    
    NSData *decoded = nil;
    
    if(szAlgorithm == "aes_ecb")
        DECODE_AND_CONVERT_NSDATA(ECB_Mode<AES>)
        
    if(szAlgorithm == "aes_cbc")
        DECODE_AND_CONVERT_NSDATA(CBC_Mode<AES>)
            
    if(szAlgorithm == "aes_cfb")
        DECODE_AND_CONVERT_NSDATA(CFB_Mode<AES>)
                
    if(szAlgorithm == "aes_ofb")
        DECODE_AND_CONVERT_NSDATA(OFB_Mode<AES>)
                    
                    
    return decoded;
}


@end
