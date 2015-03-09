//
//  Cryptor.h
//  Encryption
//
//  Created by Mani on 14.12.14.
//  Copyright (c) 2014 Mani. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Cryptor : NSObject

// Hex-Encoding / Hex-Decoding
+(NSString *)hex_encode:(NSData *)data;
+(NSString *)hex_encode:(NSData *)data useUpperCase:(BOOL)upperCase;
+(NSString *)hex_encode:(NSData *)data useUpperCase:(BOOL)upperCase withGroupSize:(int)groupSize withGroupDelimiter:(NSString *)groupDelimiter;
+(NSData *)hex_decode:(NSString *)data;

// Base64-Encoding / Base64-Decoding
+(NSString *)base64_encode:(NSData *)data;
+(NSString *)base64_encode:(NSData *)data insertLineBreaks:(BOOL)lineBreaks;
+(NSString *)base64_encode:(NSData *)data insertLineBreaks:(BOOL)lineBreaks maxLineLength:(int)lineLength;
+(NSData *)base64_decode:(NSString *)data;

+(NSData *)encode:(NSString *)algorithm withKey:(NSData *)key withData:(NSData *)data withIV:(NSData *)iv;
+(NSData *)decode:(NSString *)algorithm withKey:(NSData *)key withData:(NSData *)data withIV:(NSData *)iv;

@end
