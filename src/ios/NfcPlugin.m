//
//  NfcPlugin.m
//  PhoneGap NFC - Cordova Plugin
//
//  (c) 2017-2020 Don Coleman

#import "NfcPlugin.h"

// What the current NFC session is going to do with the tag once it is connected
typedef NS_ENUM(NSInteger, NfcSessionMode) {
    NfcSessionModeRead = 0,
    NfcSessionModeWrite,
    NfcSessionModeLock
};

// Completion handler used by the tag formatting code. dataAreaSize is the number of
// bytes available for the NDEF TLV area once the tag has been formatted.
typedef void (^NfcFormatCompletion)(NSUInteger dataAreaSize, NSError * _Nullable error);

// NFC Forum Type 2 Tag (MIFARE Ultralight, NTAG) memory layout and commands
static const uint8_t kT2TCommandRead = 0x30;              // READ 4 pages (16 bytes)
static const uint8_t kT2TCommandWrite = 0xA2;             // WRITE 1 page (4 bytes)
static const uint8_t kT2TPageSize = 4;
static const uint8_t kT2TCapabilityContainerPage = 3;
static const uint8_t kT2TDataStartPage = 4;

// NDEF TLV constants shared by Type 2 and Type 5 tags
static const uint8_t kNdefMagicNumber = 0xE1;
static const uint8_t kNdefMagicNumberExtended = 0xE2;     // Type 5 with 2 byte addressing
static const uint8_t kNdefMessageTLV = 0x03;
static const uint8_t kNdefTerminatorTLV = 0xFE;
static const uint8_t kT2TVersion = 0x10;                  // Type 2 mapping version 1.0
static const uint8_t kT5TVersionAndAccess = 0x40;         // Type 5 mapping version 1.0, read / write

// ISO 15693 request flags. Numeric values are used so the plugin compiles with the
// enum names from both the iOS 13 SDK (RequestFlag) and the iOS 14+ SDK (NFCISO15693RequestFlag).
static const uint8_t kISO15693FlagHighDataRate = 0x02;
static const uint8_t kISO15693FlagOption = 0x40;

// NFCReaderError codes that are not errors for this plugin
static const NSInteger kNdefReaderSessionErrorZeroLengthMessage = 403;

@interface NfcPlugin() {
    NSString* sessionCallbackId;
    NSString* channelCallbackId;
    id<NFCNDEFTag> connectedTag API_AVAILABLE(ios(13.0));
    NFCNDEFStatus connectedTagStatus API_AVAILABLE(ios(13.0));
    NSUInteger connectedTagCapacity;
}
@property (nonatomic, assign) NfcSessionMode sessionMode;
@property (nonatomic, assign) BOOL shouldUseTagReaderSession;
@property (nonatomic, assign) BOOL sendCallbackOnSessionStart;
@property (nonatomic, assign) BOOL returnTagInCallback;
@property (nonatomic, assign) BOOL returnTagInEvent;
@property (nonatomic, assign) BOOL keepSessionOpen;
@property (nonatomic, assign) BOOL formatBeforeWrite;
@property (strong, nonatomic) NSString *alertMessage;
@property (strong, nonatomic) NFCReaderSession *nfcSession API_AVAILABLE(ios(11.0));
@property (strong, nonatomic) NFCNDEFMessage *messageToWrite API_AVAILABLE(ios(11.0));
@end

@implementation NfcPlugin

- (void)pluginInitialize {

    NSLog(@"PhoneGap NFC - Cordova Plugin");
    NSLog(@"(c) 2017-2020 Don Coleman");

    [super pluginInitialize];

    if (@available(iOS 11, *)) {
        if (![NFCNDEFReaderSession readingAvailable]) {
            NSLog(@"NFC Support is NOT available");
        }
    } else {
        NSLog(@"NFC Support is NOT available before iOS 11");
    }
}

#pragma mark - Cordova Plugin Methods

- (void)channel:(CDVInvokedUrlCommand *)command {
    // the channel is used to send NFC tag data to the web view
    channelCallbackId = [command.callbackId copy];
}

- (void)beginSession:(CDVInvokedUrlCommand*)command {
    NSLog(@"beginSession");
    NSLog(@"WARNING: beginSession is deprecated. Use scanNdef or scanTag.");

    self.shouldUseTagReaderSession = NO;
    self.sendCallbackOnSessionStart = YES;  // Not sure why we were doing this
    self.returnTagInCallback = NO;
    self.returnTagInEvent = YES;
    self.keepSessionOpen = NO;
    self.alertMessage = @"Hold near NFC tag to scan.";

    [self startScanSession:command];
}

- (void)scanNdef:(CDVInvokedUrlCommand*)command {
    NSLog(@"scanNdef");

    NSDictionary *options = [self optionsFromCommand:command atIndex:0];

    self.shouldUseTagReaderSession = NO;
    self.sendCallbackOnSessionStart = NO;
    self.returnTagInCallback = YES;
    self.returnTagInEvent = NO;
    self.keepSessionOpen = [self boolOption:options key:@"keepSessionOpen" defaultValue:NO];
    self.alertMessage = [self stringOption:options key:@"alertMessage" defaultValue:@"Hold near NFC tag to scan."];

    [self startScanSession:command];
}

- (void)scanTag:(CDVInvokedUrlCommand*)command {
    NSLog(@"scanTag");

    NSDictionary *options = [self optionsFromCommand:command atIndex:0];

    self.shouldUseTagReaderSession = YES;
    self.sendCallbackOnSessionStart = NO;
    self.returnTagInCallback = YES;
    self.returnTagInEvent = NO;
    self.keepSessionOpen = [self boolOption:options key:@"keepSessionOpen" defaultValue:NO];
    self.alertMessage = [self stringOption:options key:@"alertMessage" defaultValue:@"Hold near NFC tag to scan."];

    [self startScanSession:command];
}

- (void)writeTag:(CDVInvokedUrlCommand*)command {
    NSLog(@"writeTag");

    NSArray *ndefData = [command argumentAtIndex:0 withDefault:nil andClass:[NSArray class]];
    NSDictionary *options = [self optionsFromCommand:command atIndex:1];

    if (@available(iOS 13.0, *)) {
        NFCNDEFMessage *message = [self ndefMessageFromJSON:ndefData];
        if (!message) {
            [self sendErrorToCommand:command message:@"Invalid NDEF Message"];
            return;
        }
        self.messageToWrite = message;
        [self startTagOperation:NfcSessionModeWrite command:command options:options defaultAlertMessage:@"Hold near writable NFC tag to update."];
    } else {
        [self sendErrorToCommand:command message:@"Writing NFC tags requires iOS 13"];
    }
}

// Erase a tag by writing a NDEF message with a single empty record, this mirrors the Android implementation
- (void)eraseTag:(CDVInvokedUrlCommand*)command {
    NSLog(@"eraseTag");

    NSDictionary *options = [self optionsFromCommand:command atIndex:0];

    if (@available(iOS 13.0, *)) {
        NFCNDEFPayload *emptyRecord = [[NFCNDEFPayload alloc] initWithFormat:NFCTypeNameFormatEmpty type:[NSData data] identifier:[NSData data] payload:[NSData data]];
        self.messageToWrite = [[NFCNDEFMessage alloc] initWithNDEFRecords:@[emptyRecord]];
        [self startTagOperation:NfcSessionModeWrite command:command options:options defaultAlertMessage:@"Hold near NFC tag to erase."];
    } else {
        [self sendErrorToCommand:command message:@"Erasing NFC tags requires iOS 13"];
    }
}

// Permanently lock the tag using the NDEF write lock command
- (void)makeReadOnly:(CDVInvokedUrlCommand*)command {
    NSLog(@"makeReadOnly");

    NSDictionary *options = [self optionsFromCommand:command atIndex:0];

    if (@available(iOS 13.0, *)) {
        [self startTagOperation:NfcSessionModeLock command:command options:options defaultAlertMessage:@"Hold near NFC tag to lock."];
    } else {
        [self sendErrorToCommand:command message:@"Locking NFC tags requires iOS 13"];
    }
}

- (void)cancelScan:(CDVInvokedUrlCommand*)command {
    NSLog(@"cancelScan");
    if (@available(iOS 11.0, *)) {
        if (self.nfcSession) {
            [self.nfcSession invalidateSession];
        }
    }
    [self clearConnectedTag];
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)invalidateSession:(CDVInvokedUrlCommand*)command {
    NSLog(@"invalidateSession");
    NSLog(@"WARNING: invalidateSession is deprecated. Use cancelScan.");

    if (@available(iOS 11.0, *)) {
        if (self.nfcSession) {
            [self.nfcSession invalidateSession];
        }
    }
    [self clearConnectedTag];
    // Always return OK. Alternately could send status from the NFCNDEFReaderSessionDelegate
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

// Nothing happens here, the event listener is registered in JavaScript
- (void)registerNdef:(CDVInvokedUrlCommand *)command {
    NSLog(@"registerNdef");
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

// Nothing happens here, the event listener is removed in JavaScript
- (void)removeNdef:(CDVInvokedUrlCommand *)command {
    NSLog(@"removeNdef");
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)enabled:(CDVInvokedUrlCommand *)command {
    NSLog(@"enabled");
    CDVPluginResult *pluginResult;
    if (@available(iOS 11.0, *)) {
        if ([NFCNDEFReaderSession readingAvailable]) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        } else {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"NO_NFC"];
        }
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"NO_NFC"];
    }
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

#pragma mark - NFCNDEFReaderSessionDelegate

// iOS 11 & 12
- (void) readerSession:(NFCNDEFReaderSession *)session didDetectNDEFs:(NSArray<NFCNDEFMessage *> *)messages API_AVAILABLE(ios(11.0)) {
    NSLog(@"NFCNDEFReaderSession didDetectNDEFs");

    session.alertMessage = @"Tag successfully read.";
    for (NFCNDEFMessage *message in messages) {
        [self fireNdefEvent: message];
    }
}

// iOS 13
- (void) readerSession:(NFCNDEFReaderSession *)session didDetectTags:(NSArray<__kindof id<NFCNDEFTag>> *)tags API_AVAILABLE(ios(13.0)) {

    if (tags.count > 1) {
        session.alertMessage = @"More than 1 tag detected. Please remove all tags and try again.";
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 500 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
            NSLog(@"restarting polling");
            [session restartPolling];
        });
        return;
    }

    id<NFCNDEFTag> tag = [tags firstObject];
    NSMutableDictionary *tagMetaData = [self getTagInfoFromNDEFTag:tag];

    [session connectToTag:tag completionHandler:^(NSError * _Nullable error) {
        if (error) {
            NSLog(@"%@", error);
            [self closeSession:session withError:@"Error connecting to tag."];
            return;
        }

        [self processNDEFTag:session tag:tag metaData:tagMetaData];
    }];

}

- (void) readerSession:(NFCNDEFReaderSession *)session didInvalidateWithError:(NSError *)error API_AVAILABLE(ios(11.0)) {
    NSLog(@"readerSession ended %@", error);
    [self sessionDidEnd:session withError:error];
}

- (void) readerSessionDidBecomeActive:(nonnull NFCReaderSession *)session API_AVAILABLE(ios(11.0)) {
    NSLog(@"readerSessionDidBecomeActive");
    [self sessionDidBecomeActive:session];
}

#pragma mark - NFCTagReaderSessionDelegate

- (void)tagReaderSessionDidBecomeActive:(NFCTagReaderSession *)session API_AVAILABLE(ios(13.0)) {
    NSLog(@"tagReaderSessionDidBecomeActive");
    [self sessionDidBecomeActive:session];
}

- (void)tagReaderSession:(NFCTagReaderSession *)session didDetectTags:(NSArray<__kindof id<NFCTag>> *)tags API_AVAILABLE(ios(13.0)) {
    NSLog(@"tagReaderSession didDetectTags");

    if (tags.count > 1) {
        session.alertMessage = @"More than 1 tag detected. Please remove all tags and try again.";
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 500 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
            NSLog(@"restarting polling");
            [session restartPolling];
        });
        return;
    }

    id<NFCTag> tag = [tags firstObject];
    NSMutableDictionary *tagMetaData = [self getTagInfo:tag];
    id<NFCNDEFTag> ndefTag = (id<NFCNDEFTag>)tag;

    [session connectToTag:tag completionHandler:^(NSError * _Nullable error) {
        if (error) {
            NSLog(@"%@", error);
            [self closeSession:session withError:@"Error connecting to tag."];
            return;
        }

        [self processNDEFTag:session tag:ndefTag metaData:tagMetaData];
    }];
}

- (void)tagReaderSession:(NFCTagReaderSession *)session didInvalidateWithError:(NSError *)error API_AVAILABLE(ios(13.0)) {
    NSLog(@"tagReaderSession ended %@", error);
    [self sessionDidEnd:session withError:error];
}

#pragma mark - Session Management

// Handles scanNdef, scanTag, and beginSession
- (void)startScanSession:(CDVInvokedUrlCommand*)command {

    self.sessionMode = NfcSessionModeRead;
    [self clearConnectedTag];

    NSLog(@"shouldUseTagReaderSession %d", self.shouldUseTagReaderSession);
    NSLog(@"callbackOnSessionStart %d", self.sendCallbackOnSessionStart);
    NSLog(@"returnTagInCallback %d", self.returnTagInCallback);
    NSLog(@"returnTagInEvent %d", self.returnTagInEvent);
    NSLog(@"keepSessionOpen %d", self.keepSessionOpen);

    if (@available(iOS 13.0, *)) {
        [self createSessionUsingTagReader:self.shouldUseTagReaderSession invalidateAfterFirstRead:YES];
        sessionCallbackId = [command.callbackId copy];
        self.nfcSession.alertMessage = self.alertMessage;
        [self.nfcSession beginSession];

    } else if (@available(iOS 11.0, *)) {
        NSLog(@"iOS < 13, using NFCNDEFReaderSession");
        self.nfcSession = [[NFCNDEFReaderSession alloc] initWithDelegate:self queue:nil invalidateAfterFirstRead:TRUE];
        sessionCallbackId = [command.callbackId copy];
        self.nfcSession.alertMessage = self.alertMessage;
        [self.nfcSession beginSession];
    } else {
        NSLog(@"iOS < 11, no NFC support");
        [self sendErrorToCommand:command message:@"NFC requires iOS 11"];
    }

}

// Handles writeTag, eraseTag and makeReadOnly. The operation either reuses the session left
// open by scanNdef / scanTag with { keepSessionOpen: true } or starts a new session.
- (void)startTagOperation:(NfcSessionMode)mode command:(CDVInvokedUrlCommand *)command options:(NSDictionary *)options defaultAlertMessage:(NSString *)defaultAlertMessage API_AVAILABLE(ios(13.0)) {

    self.sessionMode = mode;
    self.sendCallbackOnSessionStart = NO;
    self.formatBeforeWrite = [self boolOption:options key:@"format" defaultValue:YES];
    self.alertMessage = [self stringOption:options key:@"alertMessage" defaultValue:defaultAlertMessage];
    BOOL useNdefReaderSession = [self boolOption:options key:@"useNdefReaderSession" defaultValue:NO];

    if (self.nfcSession && self.nfcSession.isReady) {

        if (!connectedTag) {
            [self sendErrorToCommand:command message:@"No tag connected. Scan a tag with keepSessionOpen before calling this method, or cancel the scan first."];
            return;
        }

        if (![connectedTag isAvailable]) {
            [self sendErrorToCommand:command message:@"Tag is no longer available. Keep the tag near the phone and scan again."];
            return;
        }

        NSLog(@"Reusing open NFC session");
        sessionCallbackId = [command.callbackId copy];
        self.keepSessionOpen = NO;          // close the session once this operation completes
        self.nfcSession.alertMessage = self.alertMessage;
        [self performTagOperation:self.nfcSession status:connectedTagStatus capacity:connectedTagCapacity tag:connectedTag statusError:nil];
        return;
    }

    [self clearConnectedTag];
    self.keepSessionOpen = NO;
    // The tag reader session gives access to the raw tag commands needed to format tags and
    // returns the tag UID. The NDEF reader session is kept as an option for tags it supports
    // but the tag reader session does not (Topaz, FeliCa without system codes).
    self.shouldUseTagReaderSession = !useNdefReaderSession;
    [self createSessionUsingTagReader:self.shouldUseTagReaderSession invalidateAfterFirstRead:NO];
    sessionCallbackId = [command.callbackId copy];
    self.nfcSession.alertMessage = self.alertMessage;
    [self.nfcSession beginSession];
}

- (void)createSessionUsingTagReader:(BOOL)useTagReaderSession invalidateAfterFirstRead:(BOOL)invalidateAfterFirstRead API_AVAILABLE(ios(13.0)) {
    if (useTagReaderSession) {
        NSLog(@"Using NFCTagReaderSession");
        self.nfcSession = [[NFCTagReaderSession alloc]
                           initWithPollingOption:(NFCPollingISO14443 | NFCPollingISO15693)
                           delegate:self queue:dispatch_get_main_queue()];
    } else {
        NSLog(@"Using NFCNDEFReaderSession");
        self.nfcSession = [[NFCNDEFReaderSession alloc] initWithDelegate:self queue:nil invalidateAfterFirstRead:invalidateAfterFirstRead];
    }
}

- (void)sessionDidEnd:(NFCReaderSession *)session withError:(NSError *)error API_AVAILABLE(ios(11.0)) {
    if (@available(iOS 13.0, *)) {
        [self clearConnectedTag];
    }
    if (self.nfcSession == session) {
        self.nfcSession = nil;
    }

    if (error.code == NFCReaderSessionInvalidationErrorFirstNDEFTagRead) { // not an error
        NSLog(@"Session ended after successful NDEF tag read");
        return;
    }

    [self sendError:error.localizedDescription];
}

- (void)clearConnectedTag {
    if (@available(iOS 13.0, *)) {
        connectedTag = nil;
        connectedTagStatus = NFCNDEFStatusNotSupported;
    }
    connectedTagCapacity = 0;
}

#pragma mark - Common NDEF Processing

- (void)processNDEFTag: (NFCReaderSession *)session tag:(__kindof id<NFCNDEFTag>)tag metaData: (NSMutableDictionary * _Nonnull)metaData API_AVAILABLE(ios(13.0)) {

    [tag queryNDEFStatusWithCompletionHandler:^(NFCNDEFStatus status, NSUInteger capacity, NSError * _Nullable error) {
        if (error) {
            NSLog(@"%@", error);
            if (self.sessionMode == NfcSessionModeWrite && self.formatBeforeWrite) {
                // Some blank tags fail the status query instead of reporting NFCNDEFStatusNotSupported.
                // Treat them as unformatted so the write can try to format them.
                [self performTagOperation:session status:NFCNDEFStatusNotSupported capacity:0 tag:tag statusError:error];
            } else if (self.sessionMode == NfcSessionModeRead && metaData[@"id"]) {
                // Tags without NDEF support (e.g. ISO 7816 smart cards) can fail the status query.
                // The serial number was read when the tag was detected, so return it like a non-NDEF tag.
                NSLog(@"Tag does not support NDEF, returning tag info");
                session.alertMessage = @"Tag successfully read.";
                [self fireTagEvent:metaData];
                [self closeSession:session];
            } else {
                [self closeSession:session withError:@"Error getting tag status."];
            }
            return;
        }

        if (self.sessionMode == NfcSessionModeRead && self.keepSessionOpen) {
            // save tag & status so they can be re-used by write, erase and makeReadOnly
            self->connectedTagStatus = status;
            self->connectedTagCapacity = capacity;
            self->connectedTag = tag;
        }

        if (self.sessionMode == NfcSessionModeRead) {
            [self readNDEFTag:session status:status capacity:capacity tag:tag metaData:metaData];
        } else {
            [self performTagOperation:session status:status capacity:capacity tag:tag statusError:nil];
        }
    }];
}

- (void)performTagOperation:(NFCReaderSession *)session status:(NFCNDEFStatus)status capacity:(NSUInteger)capacity tag:(id<NFCNDEFTag>)tag statusError:(NSError * _Nullable)statusError API_AVAILABLE(ios(13.0)) {
    switch (self.sessionMode) {
        case NfcSessionModeWrite:
            [self writeNDEFTag:session status:status capacity:capacity tag:tag statusError:statusError];
            break;
        case NfcSessionModeLock:
            [self lockNDEFTag:session status:status tag:tag];
            break;
        default:
            [self closeSession:session withError:@"Unexpected session mode."];
            break;
    }
}

- (void)readNDEFTag:(NFCReaderSession * _Nonnull)session status:(NFCNDEFStatus)status capacity:(NSUInteger)capacity tag:(id<NFCNDEFTag>)tag metaData:(NSMutableDictionary * _Nonnull)metaData  API_AVAILABLE(ios(13.0)){

    if (status == NFCNDEFStatusNotSupported) {
        NSLog(@"Tag does not support NDEF");
        session.alertMessage = @"Tag successfully read.";
        [self fireTagEvent:metaData];
        [self closeSession:session];
        return;
    }

    if (status == NFCNDEFStatusReadOnly) {
        metaData[@"isWritable"] = @FALSE;
    } else if (status == NFCNDEFStatusReadWrite) {
        metaData[@"isWritable"] = @TRUE;
    }
    metaData[@"maxSize"] = @(capacity);

    [tag readNDEFWithCompletionHandler:^(NFCNDEFMessage * _Nullable message, NSError * _Nullable error) {

        // Error Code=403 "NDEF tag does not contain any NDEF message" is not an error for this plugin
        if (error && error.code != kNdefReaderSessionErrorZeroLengthMessage) {
            NSLog(@"%@", error);
            [self closeSession:session withError:@"Read Failed."];
            return;
        } else {
            NSLog(@"%@", message);
            session.alertMessage = @"Tag successfully read.";
            [self fireNdefEvent:message metaData:metaData];
            [self closeSession:session];
        }

    }];

}

- (void)writeNDEFTag:(NFCReaderSession * _Nonnull)session status:(NFCNDEFStatus)status capacity:(NSUInteger)capacity tag:(id<NFCNDEFTag>)tag statusError:(NSError * _Nullable)statusError API_AVAILABLE(ios(13.0)){
    switch (status) {
        case NFCNDEFStatusNotSupported: {

            if (!self.formatBeforeWrite) {
                if (statusError) {
                    [self closeSession:session withError:[NSString stringWithFormat:@"Error getting tag status. %@", statusError.localizedDescription]];
                } else {
                    [self closeSession:session withError:@"Tag is not NDEF formatted."];
                }
                return;
            }

            NSLog(@"Tag is not NDEF formatted, attempting to format");
            session.alertMessage = @"Formatting NFC tag.";

            [self formatTag:tag completionHandler:^(NSUInteger dataAreaSize, NSError * _Nullable error) {
                if (error) {
                    NSLog(@"%@", error);
                    [self closeSession:session withError:error.localizedDescription];
                    return;
                }

                // Query the status again so CoreNFC picks up the new capability container and
                // performs the NDEF write. If CoreNFC still reports the tag as unsupported, write
                // the NDEF message with raw tag commands.
                [tag queryNDEFStatusWithCompletionHandler:^(NFCNDEFStatus newStatus, NSUInteger newCapacity, NSError * _Nullable queryError) {
                    if (!queryError && newStatus == NFCNDEFStatusReadWrite) {
                        NSLog(@"Tag formatted, CoreNFC reports NDEF read/write with capacity %lu", (unsigned long)newCapacity);
                        [self writeMessageToTag:tag session:session capacity:newCapacity];
                    } else {
                        NSLog(@"Tag formatted, writing NDEF message with raw commands (status %ld, %@)", (long)newStatus, queryError);
                        [self rawWriteMessageToTag:tag session:session dataAreaSize:dataAreaSize];
                    }
                }];
            }];
            break;
        }
        case NFCNDEFStatusReadOnly:
            [self closeSession:session withError:@"Tag is read only."];
            break;
        case NFCNDEFStatusReadWrite:
            [self writeMessageToTag:tag session:session capacity:capacity];
            break;
        default:
            [self closeSession:session withError:@"Unknown NDEF tag status."];
    }
}

// Write self.messageToWrite using CoreNFC
- (void)writeMessageToTag:(id<NFCNDEFTag>)tag session:(NFCReaderSession *)session capacity:(NSUInteger)capacity API_AVAILABLE(ios(13.0)) {

    NSUInteger messageSize = [self encodeNDEFMessage:self.messageToWrite].length;
    if (capacity > 0 && messageSize > capacity) {
        [self closeSession:session withError:[NSString stringWithFormat:@"Tag capacity is %lu bytes, message is %lu bytes.", (unsigned long)capacity, (unsigned long)messageSize]];
        return;
    }

    [tag writeNDEF:self.messageToWrite completionHandler:^(NSError * _Nullable error) {
        if (error) {
            NSLog(@"%@", error);
            [self closeSession:session withError:[NSString stringWithFormat:@"Write failed. %@", error.localizedDescription]];
        } else {
            [self finishWrite:session];
        }
    }];
}

// Write self.messageToWrite with raw tag commands. Used after formatting when CoreNFC does not
// refresh the NDEF status of the tag within the session.
- (void)rawWriteMessageToTag:(id<NFCNDEFTag>)tag session:(NFCReaderSession *)session dataAreaSize:(NSUInteger)dataAreaSize API_AVAILABLE(ios(13.0)) {

    NSData *tlv = [self ndefTLVForMessage:self.messageToWrite];
    if (dataAreaSize > 0 && tlv.length > dataAreaSize) {
        [self closeSession:session withError:[NSString stringWithFormat:@"Tag capacity is %lu bytes, message is %lu bytes.", (unsigned long)dataAreaSize, (unsigned long)tlv.length]];
        return;
    }

    NSObject *tagObject = (NSObject *)tag;
    void (^completion)(NSError * _Nullable) = ^(NSError * _Nullable error) {
        if (error) {
            NSLog(@"%@", error);
            [self closeSession:session withError:[NSString stringWithFormat:@"Write failed. %@", error.localizedDescription]];
        } else {
            [self finishWrite:session];
        }
    };

    if ([tagObject conformsToProtocol:@protocol(NFCMiFareTag)]) {
        [self t2tWriteData:tlv toTag:(id<NFCMiFareTag>)tag startingAtPage:kT2TDataStartPage completionHandler:completion];
    } else if ([tagObject conformsToProtocol:@protocol(NFCISO15693Tag)]) {
        [self t5tWriteNDEFArea:tlv toTag:(id<NFCISO15693Tag>)tag completionHandler:completion];
    } else {
        [self closeSession:session withError:@"Write failed. Tag type does not support raw NDEF writes."];
    }
}

- (void)finishWrite:(NFCReaderSession *)session API_AVAILABLE(ios(13.0)) {
    session.alertMessage = @"Wrote data to NFC tag.";
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:sessionCallbackId];
    [self closeSession:session];
}

- (void)lockNDEFTag:(NFCReaderSession * _Nonnull)session status:(NFCNDEFStatus)status tag:(id<NFCNDEFTag>)tag API_AVAILABLE(ios(13.0)) {
    switch (status) {
        case NFCNDEFStatusNotSupported:
            [self closeSession:session withError:@"Tag is not NDEF formatted."];
            break;
        case NFCNDEFStatusReadOnly:
            [self closeSession:session withError:@"Tag is already read only."];
            break;
        case NFCNDEFStatusReadWrite: {
            [tag writeLockWithCompletionHandler:^(NSError * _Nullable error) {
                if (error) {
                    NSLog(@"%@", error);
                    [self closeSession:session withError:[NSString stringWithFormat:@"Could not make tag read only. %@", error.localizedDescription]];
                } else {
                    session.alertMessage = @"Tag is now read only.";
                    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:self->sessionCallbackId];
                    [self closeSession:session];
                }
            }];
            break;
        }
        default:
            [self closeSession:session withError:@"Unknown NDEF tag status."];
    }
}

#pragma mark - Tag Formatting

// CoreNFC has no API to format a tag, so blank tags are formatted by writing the NDEF
// capability container with raw commands. This is supported for NFC Forum Type 2 tags
// (MIFARE Ultralight, NTAG) and Type 5 tags (ISO 15693). Android formats the same way
// through NdefFormatable.
- (void)formatTag:(id<NFCNDEFTag>)tag completionHandler:(NfcFormatCompletion)completion API_AVAILABLE(ios(13.0)) {
    NSObject *tagObject = (NSObject *)tag;

    if ([tagObject conformsToProtocol:@protocol(NFCMiFareTag)]) {
        id<NFCMiFareTag> mifareTag = (id<NFCMiFareTag>)tag;
        if (mifareTag.mifareFamily == NFCMiFareUltralight) {
            [self formatType2Tag:mifareTag completionHandler:completion];
        } else {
            completion(0, [self errorWithMessage:@"Tag is not NDEF formatted. Only MIFARE Ultralight and NTAG tags can be formatted on iOS."]);
        }
    } else if ([tagObject conformsToProtocol:@protocol(NFCISO15693Tag)]) {
        [self formatType5Tag:(id<NFCISO15693Tag>)tag completionHandler:completion];
    } else {
        completion(0, [self errorWithMessage:@"Tag is not NDEF formatted and can not be formatted in this session."]);
    }
}

// Type 2 Tag: write the capability container (page 3) and an empty NDEF TLV (page 4)
- (void)formatType2Tag:(id<NFCMiFareTag>)tag completionHandler:(NfcFormatCompletion)completion API_AVAILABLE(ios(13.0)) {

    [self t2tReadPage:0 fromTag:tag completionHandler:^(NSData * _Nullable header, NSError * _Nullable error) {
        if (error) {
            completion(0, [self errorWithMessage:@"Format failed. Unable to read tag header." underlyingError:error]);
            return;
        }

        const uint8_t *bytes = header.bytes;
        uint8_t cc0 = bytes[12], cc1 = bytes[13], cc2 = bytes[14], cc3 = bytes[15];
        BOOL ccBlank = (cc0 | cc1 | cc2 | cc3) == 0;
        NSLog(@"Type 2 capability container %02X %02X %02X %02X", cc0, cc1, cc2, cc3);

        if (!ccBlank && cc0 != kNdefMagicNumber) {
            completion(0, [self errorWithMessage:@"Format failed. Tag capability container contains non-NDEF data."]);
            return;
        }
        if (!ccBlank && (cc3 & 0x0F) != 0) {
            completion(0, [self errorWithMessage:@"Tag is read only."]);
            return;
        }

        [self t2tDataAreaSizeForTag:tag header:header completionHandler:^(NSUInteger detectedSize, NSError * _Nullable sizeError) {
            if (sizeError) {
                completion(0, [self errorWithMessage:@"Format failed. Unable to determine tag memory size." underlyingError:sizeError]);
                return;
            }

            NSUInteger dataAreaSize = ccBlank ? detectedSize : (NSUInteger)cc2 * 8;
            NSLog(@"Type 2 data area size %lu bytes", (unsigned long)dataAreaSize);

            void (^writeEmptyTLV)(void) = ^{
                uint8_t tlv[4] = { kNdefMessageTLV, 0x00, kNdefTerminatorTLV, 0x00 };
                [self t2tWritePage:kT2TDataStartPage data:[NSData dataWithBytes:tlv length:4] toTag:tag completionHandler:^(NSError * _Nullable tlvError) {
                    if (tlvError) {
                        completion(0, [self errorWithMessage:@"Format failed. Unable to write NDEF TLV." underlyingError:tlvError]);
                    } else {
                        completion(dataAreaSize, nil);
                    }
                }];
            };

            if (ccBlank) {
                uint8_t cc[4] = { kNdefMagicNumber, kT2TVersion, (uint8_t)(dataAreaSize / 8), 0x00 };
                [self t2tWritePage:kT2TCapabilityContainerPage data:[NSData dataWithBytes:cc length:4] toTag:tag completionHandler:^(NSError * _Nullable ccError) {
                    if (ccError) {
                        completion(0, [self errorWithMessage:@"Format failed. Unable to write capability container." underlyingError:ccError]);
                    } else {
                        writeEmptyTLV();
                    }
                }];
            } else {
                writeEmptyTLV();
            }
        }];
    }];
}

// Determines the size of the Type 2 data area (pages 4 and up) without sending commands the
// tag might reject. READ returns 4 pages and rolls over to page 0 after the last page, so
// reading candidate last pages reveals the total number of pages. The candidates are ordered
// so each read is a valid page on every tag that reached it.
- (void)t2tDataAreaSizeForTag:(id<NFCMiFareTag>)tag header:(NSData *)header completionHandler:(void (^)(NSUInteger dataAreaSize, NSError * _Nullable error))completion API_AVAILABLE(ios(13.0)) {

    // last page => data area size in bytes, values match the capability containers NXP ships
    NSArray<NSArray<NSNumber *> *> *candidates = @[
        @[@15,  @48],    // MIFARE Ultralight (MF0ICU1)
        @[@19,  @48],    // MIFARE Ultralight EV1 (MF0UL11), NTAG210
        @[@40,  @128],   // MIFARE Ultralight EV1 (MF0UL21), NTAG212
        @[@41,  @144],   // NTAG203
        @[@44,  @144],   // NTAG213
        @[@47,  @144],   // MIFARE Ultralight C
        @[@134, @496],   // NTAG215
        @[@230, @872],   // NTAG216
    ];

    [self t2tProbeCandidates:candidates index:0 header:header tag:tag completionHandler:completion];
}

- (void)t2tProbeCandidates:(NSArray<NSArray<NSNumber *> *> *)candidates index:(NSUInteger)index header:(NSData *)header tag:(id<NFCMiFareTag>)tag completionHandler:(void (^)(NSUInteger dataAreaSize, NSError * _Nullable error))completion API_AVAILABLE(ios(13.0)) {

    if (index >= candidates.count) {
        // larger than any known tag, use the largest known size
        completion([[[candidates lastObject] lastObject] unsignedIntegerValue], nil);
        return;
    }

    uint8_t page = [candidates[index][0] unsignedCharValue];
    NSUInteger size = [candidates[index][1] unsignedIntegerValue];

    [self t2tReadPage:page fromTag:tag completionHandler:^(NSData * _Nullable response, NSError * _Nullable error) {
        if (error) {
            completion(0, error);
            return;
        }

        // when READ rolls over, bytes 4-11 of the response are pages 0 and 1 (the UID)
        BOOL rolledOver = memcmp((const uint8_t *)response.bytes + 4, header.bytes, 8) == 0;
        if (rolledOver) {
            NSLog(@"Type 2 tag has %d pages", page + 1);
            completion(size, nil);
        } else {
            [self t2tProbeCandidates:candidates index:index + 1 header:header tag:tag completionHandler:completion];
        }
    }];
}

// READ command, returns 16 bytes (4 pages)
- (void)t2tReadPage:(uint8_t)page fromTag:(id<NFCMiFareTag>)tag completionHandler:(void (^)(NSData * _Nullable response, NSError * _Nullable error))completion API_AVAILABLE(ios(13.0)) {
    uint8_t command[2] = { kT2TCommandRead, page };
    [tag sendMiFareCommand:[NSData dataWithBytes:command length:2] completionHandler:^(NSData * _Nonnull response, NSError * _Nullable error) {
        if (!error && response.length < 16) {
            error = [self errorWithMessage:[NSString stringWithFormat:@"Unexpected response reading page %d.", page]];
        }
        completion(response, error);
    }];
}

// WRITE command for a single 4 byte page. The page is read back to verify the write, which also
// makes the result independent of how CoreNFC reports the 4 bit ACK / NAK response.
- (void)t2tWritePage:(uint8_t)page data:(NSData *)data toTag:(id<NFCMiFareTag>)tag completionHandler:(void (^)(NSError * _Nullable error))completion API_AVAILABLE(ios(13.0)) {

    NSMutableData *command = [NSMutableData dataWithCapacity:2 + kT2TPageSize];
    uint8_t prefix[2] = { kT2TCommandWrite, page };
    [command appendBytes:prefix length:2];
    [command appendData:[self data:data paddedToLength:kT2TPageSize]];

    [tag sendMiFareCommand:command completionHandler:^(NSData * _Nonnull response, NSError * _Nullable writeError) {
        [self t2tReadPage:page fromTag:tag completionHandler:^(NSData * _Nullable readBack, NSError * _Nullable readError) {
            if (readError) {
                completion(writeError ?: readError);
                return;
            }
            NSData *expected = [self data:data paddedToLength:kT2TPageSize];
            NSData *actual = [readBack subdataWithRange:NSMakeRange(0, kT2TPageSize)];
            if ([expected isEqualToData:actual]) {
                completion(nil);
            } else {
                completion(writeError ?: [self errorWithMessage:[NSString stringWithFormat:@"Verification of page %d failed.", page]]);
            }
        }];
    }];
}

// Writes data page by page starting at startPage
- (void)t2tWriteData:(NSData *)data toTag:(id<NFCMiFareTag>)tag startingAtPage:(uint8_t)startPage completionHandler:(void (^)(NSError * _Nullable error))completion API_AVAILABLE(ios(13.0)) {
    [self t2tWriteData:[self data:data paddedToMultipleOf:kT2TPageSize] toTag:tag page:startPage offset:0 completionHandler:completion];
}

- (void)t2tWriteData:(NSData *)data toTag:(id<NFCMiFareTag>)tag page:(NSUInteger)page offset:(NSUInteger)offset completionHandler:(void (^)(NSError * _Nullable error))completion API_AVAILABLE(ios(13.0)) {
    if (offset >= data.length) {
        completion(nil);
        return;
    }
    if (page > 0xFF) {
        completion([self errorWithMessage:@"Message does not fit in the tag."]);
        return;
    }
    NSData *chunk = [data subdataWithRange:NSMakeRange(offset, kT2TPageSize)];
    [self t2tWritePage:(uint8_t)page data:chunk toTag:tag completionHandler:^(NSError * _Nullable error) {
        if (error) {
            completion(error);
        } else {
            [self t2tWriteData:data toTag:tag page:page + 1 offset:offset + kT2TPageSize completionHandler:completion];
        }
    }];
}

// Type 5 Tag: write the capability container and an empty NDEF TLV starting at block 0
- (void)formatType5Tag:(id<NFCISO15693Tag>)tag completionHandler:(NfcFormatCompletion)completion API_AVAILABLE(ios(13.0)) {

    [tag getSystemInfoWithRequestFlag:kISO15693FlagHighDataRate completionHandler:^(NSInteger dsfid, NSInteger afi, NSInteger blockSize, NSInteger blockCount, NSInteger icReference, NSError * _Nullable error) {
        if (error) {
            completion(0, [self errorWithMessage:@"Format failed. Unable to read tag system information." underlyingError:error]);
            return;
        }

        [tag readSingleBlockWithRequestFlags:kISO15693FlagHighDataRate blockNumber:0 completionHandler:^(NSData * _Nonnull block0, NSError * _Nullable readError) {
            if (readError || block0.length < 4) {
                completion(0, [self errorWithMessage:@"Format failed. Unable to read tag block 0." underlyingError:readError]);
                return;
            }

            // The block size reported by the tag is used as the real block length, the first block
            // read tells us exactly how many bytes are in a block.
            NSUInteger realBlockSize = block0.length;
            NSUInteger count = blockCount > 0 ? (NSUInteger)blockCount : 0;
            if (count > 256) {
                count = 256;    // single byte block addressing
            }
            if (count == 0) {
                completion(0, [self errorWithMessage:@"Format failed. Unable to determine tag memory size."]);
                return;
            }

            NSUInteger memorySize = realBlockSize * count;
            NSUInteger ndefAreaSize = memorySize > 4 ? memorySize - 4 : 0;     // the capability container uses 4 bytes
            if (ndefAreaSize / 8 > 0xFF) {
                ndefAreaSize = 0xFF * 8;    // keep the 4 byte capability container
            }
            ndefAreaSize = (ndefAreaSize / 8) * 8;
            NSLog(@"Type 5 tag %lu blocks of %lu bytes, NDEF area %lu bytes", (unsigned long)count, (unsigned long)realBlockSize, (unsigned long)ndefAreaSize);

            const uint8_t *bytes = block0.bytes;
            BOOL hasCC = bytes[0] == kNdefMagicNumber || bytes[0] == kNdefMagicNumberExtended;
            BOOL ccBlank = YES;
            for (NSUInteger i = 0; i < 4; i++) {
                if (bytes[i] != 0) {
                    ccBlank = NO;
                }
            }

            if (!hasCC && !ccBlank) {
                completion(0, [self errorWithMessage:@"Format failed. Tag capability container contains non-NDEF data."]);
                return;
            }
            if (hasCC && (bytes[1] & 0x0F) != 0) {
                completion(0, [self errorWithMessage:@"Tag is read only."]);
                return;
            }
            if (hasCC && bytes[2] != 0) {
                ndefAreaSize = (NSUInteger)bytes[2] * 8;    // trust the existing capability container
            }

            NSMutableData *area = [NSMutableData new];
            if (hasCC) {
                [area appendData:[block0 subdataWithRange:NSMakeRange(0, 4)]];
            } else {
                uint8_t cc[4] = { kNdefMagicNumber, kT5TVersionAndAccess, (uint8_t)(ndefAreaSize / 8), 0x00 };
                [area appendBytes:cc length:4];
            }
            uint8_t tlv[4] = { kNdefMessageTLV, 0x00, kNdefTerminatorTLV, 0x00 };
            [area appendBytes:tlv length:4];

            [self t5tWriteData:[self data:area paddedToMultipleOf:realBlockSize] toTag:tag blockSize:realBlockSize block:0 offset:0 completionHandler:^(NSError * _Nullable writeError) {
                if (writeError) {
                    completion(0, [self errorWithMessage:@"Format failed. Unable to write capability container." underlyingError:writeError]);
                } else {
                    completion(ndefAreaSize, nil);
                }
            }];
        }];
    }];
}

// Writes the NDEF TLV area of a Type 5 tag. The TLV starts right after the 4 byte capability
// container so block 0 is rewritten with the existing capability container followed by the TLV.
- (void)t5tWriteNDEFArea:(NSData *)tlv toTag:(id<NFCISO15693Tag>)tag completionHandler:(void (^)(NSError * _Nullable error))completion API_AVAILABLE(ios(13.0)) {
    [tag readSingleBlockWithRequestFlags:kISO15693FlagHighDataRate blockNumber:0 completionHandler:^(NSData * _Nonnull block0, NSError * _Nullable error) {
        if (error || block0.length < 4) {
            completion(error ?: [self errorWithMessage:@"Unable to read tag block 0."]);
            return;
        }
        NSUInteger blockSize = block0.length;
        NSMutableData *area = [NSMutableData dataWithData:[block0 subdataWithRange:NSMakeRange(0, 4)]];
        [area appendData:tlv];
        [self t5tWriteData:[self data:area paddedToMultipleOf:blockSize] toTag:tag blockSize:blockSize block:0 offset:0 completionHandler:completion];
    }];
}

- (void)t5tWriteData:(NSData *)data toTag:(id<NFCISO15693Tag>)tag blockSize:(NSUInteger)blockSize block:(NSUInteger)block offset:(NSUInteger)offset completionHandler:(void (^)(NSError * _Nullable error))completion API_AVAILABLE(ios(13.0)) {
    if (offset >= data.length) {
        completion(nil);
        return;
    }
    if (block > 0xFF) {
        completion([self errorWithMessage:@"Message does not fit in the tag."]);
        return;
    }
    NSData *chunk = [data subdataWithRange:NSMakeRange(offset, blockSize)];
    [self t5tWriteBlock:(uint8_t)block data:chunk toTag:tag completionHandler:^(NSError * _Nullable error) {
        if (error) {
            completion(error);
        } else {
            [self t5tWriteData:data toTag:tag blockSize:blockSize block:block + 1 offset:offset + blockSize completionHandler:completion];
        }
    }];
}

// Write a single block and read it back to verify. Some tags (NXP ICODE) require the option
// flag for write commands, so the write is retried with the option flag when the first attempt fails.
- (void)t5tWriteBlock:(uint8_t)block data:(NSData *)data toTag:(id<NFCISO15693Tag>)tag completionHandler:(void (^)(NSError * _Nullable error))completion API_AVAILABLE(ios(13.0)) {

    void (^verify)(NSError * _Nullable) = ^(NSError * _Nullable writeError) {
        [tag readSingleBlockWithRequestFlags:kISO15693FlagHighDataRate blockNumber:block completionHandler:^(NSData * _Nonnull readBack, NSError * _Nullable readError) {
            if (readError) {
                completion(writeError ?: readError);
            } else if ([readBack isEqualToData:data]) {
                completion(nil);
            } else {
                completion(writeError ?: [self errorWithMessage:[NSString stringWithFormat:@"Verification of block %d failed.", block]]);
            }
        }];
    };

    [tag writeSingleBlockWithRequestFlags:kISO15693FlagHighDataRate blockNumber:block dataBlock:data completionHandler:^(NSError * _Nullable error) {
        if (!error) {
            verify(nil);
            return;
        }
        NSLog(@"Write block %d failed (%@), retrying with option flag", block, error);
        [tag writeSingleBlockWithRequestFlags:(kISO15693FlagHighDataRate | kISO15693FlagOption) blockNumber:block dataBlock:data completionHandler:^(NSError * _Nullable retryError) {
            verify(retryError);
        }];
    }];
}

#pragma mark - Tag Reader Helper Functions

// Gets the tag meta data - type, uid and type specific details
- (NSMutableDictionary *) getTagInfo:(id<NFCTag>)tag API_AVAILABLE(ios(13.0)) {

    NSMutableDictionary *tagInfo = [NSMutableDictionary new];

    NSData *uid;
    NSString *type;

    switch (tag.type) {
        case NFCTagTypeFeliCa: {
            type = @"NFCTagTypeFeliCa";
            id<NFCFeliCaTag> feliCaTag = [tag asNFCFeliCaTag];
            uid = feliCaTag.currentIDm;
            if (feliCaTag.currentSystemCode) {
                tagInfo[@"systemCode"] = [self uint8ArrayFromNSData:feliCaTag.currentSystemCode];
            }
            break;
        }
        case NFCTagTypeMiFare: {
            type = @"NFCTagTypeMiFare";
            id<NFCMiFareTag> mifareTag = [tag asNFCMiFareTag];
            uid = mifareTag.identifier;
            tagInfo[@"mifareFamily"] = [self mifareFamilyName:mifareTag.mifareFamily];
            if (mifareTag.historicalBytes) {
                tagInfo[@"historicalBytes"] = [self uint8ArrayFromNSData:mifareTag.historicalBytes];
            }
            break;
        }
        case NFCTagTypeISO15693: {
            type = @"NFCTagTypeISO15693";
            id<NFCISO15693Tag> isoTag = [tag asNFCISO15693Tag];
            uid = isoTag.identifier;
            tagInfo[@"icManufacturerCode"] = @(isoTag.icManufacturerCode);
            if (isoTag.icSerialNumber) {
                tagInfo[@"icSerialNumber"] = [self uint8ArrayFromNSData:isoTag.icSerialNumber];
            }
            break;
        }
        case NFCTagTypeISO7816Compatible: {
            type = @"NFCTagTypeISO7816Compatible";
            id<NFCISO7816Tag> isoTag = [tag asNFCISO7816Tag];
            uid = isoTag.identifier;
            if (isoTag.initialSelectedAID) {
                tagInfo[@"initialSelectedAID"] = isoTag.initialSelectedAID;
            }
            if (isoTag.historicalBytes) {
                tagInfo[@"historicalBytes"] = [self uint8ArrayFromNSData:isoTag.historicalBytes];
            }
            if (isoTag.applicationData) {
                tagInfo[@"applicationData"] = [self uint8ArrayFromNSData:isoTag.applicationData];
            }
            break;
        }
        default:
            type = @"Unknown";
            uid = nil;
            break;
    }

    NSLog(@"getTagInfo: %@ with uid %@", type, uid);

    [tagInfo setValue:type forKey:@"type"];
    if (uid.length > 0) {
        [tagInfo setValue:[self uint8ArrayFromNSData:uid] forKey:@"id"];
    }
    return tagInfo;
}

// The tags returned by NFCNDEFReaderSession implement the NFCTag protocol on current iOS
// versions. When they do, the UID and tag type are included in the result.
- (NSMutableDictionary *) getTagInfoFromNDEFTag:(id<NFCNDEFTag>)tag API_AVAILABLE(ios(13.0)) {
    NSObject *tagObject = (NSObject *)tag;
    if ([tagObject conformsToProtocol:@protocol(NFCTag)] && [tagObject respondsToSelector:@selector(type)]) {
        @try {
            return [self getTagInfo:(id<NFCTag>)tag];
        } @catch (NSException *exception) {
            NSLog(@"Unable to get tag info from NDEF tag: %@", exception);
        }
    }
    return [NSMutableDictionary new];
}

- (NSString *) mifareFamilyName:(NFCMiFareFamily)family API_AVAILABLE(ios(13.0)) {
    switch (family) {
        case NFCMiFareUltralight:
            return @"Ultralight";
        case NFCMiFarePlus:
            return @"Plus";
        case NFCMiFareDESFire:
            return @"DESFire";
        default:
            return @"Unknown";
    }
}

#pragma mark - internal implementation

- (NSDictionary *) optionsFromCommand:(CDVInvokedUrlCommand *)command atIndex:(NSUInteger)index {
    NSDictionary *options = [command argumentAtIndex:index withDefault:nil andClass:[NSDictionary class]];
    return options ?: @{};
}

- (BOOL) boolOption:(NSDictionary *)options key:(NSString *)key defaultValue:(BOOL)defaultValue {
    id value = options[key];
    if (value == nil || value == [NSNull null] || ![value respondsToSelector:@selector(boolValue)]) {
        return defaultValue;
    }
    return [value boolValue];
}

- (NSString *) stringOption:(NSDictionary *)options key:(NSString *)key defaultValue:(NSString *)defaultValue {
    id value = options[key];
    if ([value isKindOfClass:[NSString class]] && [value length] > 0) {
        return value;
    }
    return defaultValue;
}

- (NSError *) errorWithMessage:(NSString *)message {
    return [NSError errorWithDomain:@"NfcPlugin" code:0 userInfo:@{ NSLocalizedDescriptionKey: message }];
}

- (NSError *) errorWithMessage:(NSString *)message underlyingError:(NSError * _Nullable)error {
    if (error) {
        return [NSError errorWithDomain:@"NfcPlugin" code:error.code userInfo:@{
            NSLocalizedDescriptionKey: [NSString stringWithFormat:@"%@ %@", message, error.localizedDescription],
            NSUnderlyingErrorKey: error
        }];
    }
    return [self errorWithMessage:message];
}

- (void) sendErrorToCommand:(CDVInvokedUrlCommand *)command message:(NSString *)message {
    NSLog(@"%@", message);
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:message];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void) sendError:(NSString *)message {
    // only send the error if the callback id exists
    if (sessionCallbackId) {
        NSLog(@"sendError: %@", message);
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:message];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:sessionCallbackId];
        sessionCallbackId = NULL;
    }
}

- (void) sessionDidBecomeActive:(NFCReaderSession *) session  API_AVAILABLE(ios(11.0)){
    if (sessionCallbackId && self.sendCallbackOnSessionStart) {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [pluginResult setKeepCallback:@YES];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:sessionCallbackId];
    }
}

- (void) closeSession:(NFCReaderSession *) session  API_AVAILABLE(ios(11.0)){

    // keep a read session open to allow writing, erasing or locking the tag
    if (self.keepSessionOpen) {
        return;
    }

    // kill the callback so the Cordova doesn't get "Session invalidated by user"
    sessionCallbackId = NULL;
    [self clearConnectedTag];
    [session invalidateSession];
}

- (void) closeSession:(NFCReaderSession *) session withError:(NSString *) errorMessage  API_AVAILABLE(ios(11.0)){
    [self sendError:errorMessage];

    // kill the callback so Cordova doesn't get "Session invalidated by user"
    sessionCallbackId = NULL;
    [self clearConnectedTag];

    if (@available(iOS 13.0, *)) {
        [session invalidateSessionWithErrorMessage:errorMessage];
    } else {
        [session invalidateSession];
    }
}

-(void) fireTagEvent:(NSDictionary *)metaData API_AVAILABLE(ios(11.0)) {
    // Data is from a tag, but still ends up as an NDEF event in Javascript
    [self fireNdefEvent:nil metaData:metaData];
}

-(void) fireNdefEvent:(NFCNDEFMessage *) ndefMessage API_AVAILABLE(ios(11.0)) {
    [self fireNdefEvent:ndefMessage metaData:nil];
}

// TODO rename method since we're using the channel or callback instead of firing an event
-(void) fireNdefEvent:(NFCNDEFMessage *) ndefMessage metaData:(NSDictionary *)metaData API_AVAILABLE(ios(11.0)) {
    NSLog(@"fireNdefEvent");

    NSMutableDictionary *nfcEvent = [NSMutableDictionary new];
    nfcEvent[@"type"] = @"ndef";
    nfcEvent[@"tag"] = [self buildTagDictionary:ndefMessage metaData:metaData];

    if (sessionCallbackId && self.returnTagInCallback) {
        NSLog(@"Sending NFC data via sessionCallbackId");
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:nfcEvent[@"tag"]];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:sessionCallbackId];
        sessionCallbackId = NULL;
    }

    if (channelCallbackId && self.returnTagInEvent) {
        NSLog(@"Sending NFC data via channelCallbackId so an NDEF event fires)");

        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:nfcEvent];
        [pluginResult setKeepCallback:[NSNumber numberWithBool:YES]];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:channelCallbackId];
    }
}

// NSDictionary representing an NFC tag
// NSData fields are converted to uint8_t arrays
-(NSDictionary *) buildTagDictionary:(NFCNDEFMessage *) ndefMessage metaData: (NSDictionary *)metaData API_AVAILABLE(ios(11.0)) {

    NSMutableDictionary *dictionary = [NSMutableDictionary new];

    // start with tag meta data
    if (metaData) {
        [dictionary setDictionary:metaData];
    }

    // convert uid from NSData to a uint8_t array
    id uid = [dictionary objectForKey:@"id"];
    if ([uid isKindOfClass:[NSData class]]) {
        dictionary[@"id"] = [self uint8ArrayFromNSData: uid];
    }

    if (ndefMessage) {
        NSMutableArray *array = [NSMutableArray new];
        for (NFCNDEFPayload *record in ndefMessage.records){
            NSDictionary* recordDictionary = [self ndefRecordToNSDictionary:record];
            [array addObject:recordDictionary];
        }
        [dictionary setObject:array forKey:@"ndefMessage"];
    }

    return [dictionary copy];
}

-(NSDictionary *) ndefRecordToNSDictionary:(NFCNDEFPayload *) ndefRecord API_AVAILABLE(ios(11.0)) {
    NSMutableDictionary *dict = [NSMutableDictionary new];
    dict[@"tnf"] = [NSNumber numberWithInt:(int)ndefRecord.typeNameFormat];
    dict[@"type"] = [self uint8ArrayFromNSData: ndefRecord.type];
    dict[@"id"] = [self uint8ArrayFromNSData: ndefRecord.identifier];
    dict[@"payload"] = [self uint8ArrayFromNSData: ndefRecord.payload];
    NSDictionary *copy = [dict copy];
    return copy;
}

// Builds a NFCNDEFMessage from the JSON records sent by JavaScript. Returns nil for invalid input.
- (NFCNDEFMessage *) ndefMessageFromJSON:(NSArray *)ndefData API_AVAILABLE(ios(13.0)) {

    if (![ndefData isKindOfClass:[NSArray class]] || ndefData.count == 0) {
        return nil;
    }

    NSMutableArray<NFCNDEFPayload*> *payloads = [NSMutableArray new];

    @try {
        for (id recordData in ndefData) {
            if (![recordData isKindOfClass:[NSDictionary class]]) {
                return nil;
            }
            NSNumber *tnfNumber = [recordData objectForKey:@"tnf"];
            NFCTypeNameFormat tnf = (uint8_t)[tnfNumber intValue];
            NSData *type = [self uint8ArrayToNSData:[recordData objectForKey:@"type"]];
            NSData *identifier = [self uint8ArrayToNSData:[recordData objectForKey:@"id"]];
            NSData *payload  = [self uint8ArrayToNSData:[recordData objectForKey:@"payload"]];
            NFCNDEFPayload *record = [[NFCNDEFPayload alloc] initWithFormat:tnf type:type identifier:identifier payload:payload];
            [payloads addObject:record];
        }
        NSLog(@"%@", payloads);
        return [[NFCNDEFMessage alloc] initWithNDEFRecords:payloads];
    } @catch(NSException *e) {
        NSLog(@"Invalid NDEF Message %@", e);
        return nil;
    }
}

// Encodes a NDEF message to bytes as described in the NFC Data Exchange Format specification
- (NSData *) encodeNDEFMessage:(NFCNDEFMessage *)message API_AVAILABLE(ios(13.0)) {

    NSMutableData *encoded = [NSMutableData new];
    NSArray<NFCNDEFPayload *> *records = message.records;
    NSUInteger count = records.count;

    for (NSUInteger index = 0; index < count; index++) {
        NFCNDEFPayload *record = records[index];
        NSData *type = record.type ?: [NSData data];
        NSData *identifier = record.identifier ?: [NSData data];
        NSData *payload = record.payload ?: [NSData data];
        BOOL shortRecord = payload.length < 256;

        uint8_t header = (uint8_t)(record.typeNameFormat & 0x07);
        if (index == 0) {
            header |= 0x80;             // message begin
        }
        if (index == count - 1) {
            header |= 0x40;             // message end
        }
        if (shortRecord) {
            header |= 0x10;             // short record
        }
        if (identifier.length > 0) {
            header |= 0x08;             // id length present
        }
        [encoded appendBytes:&header length:1];

        uint8_t typeLength = (uint8_t)type.length;
        [encoded appendBytes:&typeLength length:1];

        if (shortRecord) {
            uint8_t payloadLength = (uint8_t)payload.length;
            [encoded appendBytes:&payloadLength length:1];
        } else {
            uint32_t length = (uint32_t)payload.length;
            uint8_t payloadLength[4] = { (uint8_t)(length >> 24), (uint8_t)(length >> 16), (uint8_t)(length >> 8), (uint8_t)length };
            [encoded appendBytes:payloadLength length:4];
        }

        if (identifier.length > 0) {
            uint8_t idLength = (uint8_t)identifier.length;
            [encoded appendBytes:&idLength length:1];
        }

        [encoded appendData:type];
        [encoded appendData:identifier];
        [encoded appendData:payload];
    }

    return encoded;
}

// NDEF Message TLV (type 0x03) containing the message, followed by a terminator TLV
- (NSData *) ndefTLVForMessage:(NFCNDEFMessage *)message API_AVAILABLE(ios(13.0)) {
    NSData *encoded = [self encodeNDEFMessage:message];
    NSMutableData *tlv = [NSMutableData new];

    uint8_t messageTLV = kNdefMessageTLV;
    [tlv appendBytes:&messageTLV length:1];

    if (encoded.length < 0xFF) {
        uint8_t length = (uint8_t)encoded.length;
        [tlv appendBytes:&length length:1];
    } else {
        uint8_t length[3] = { 0xFF, (uint8_t)(encoded.length >> 8), (uint8_t)(encoded.length & 0xFF) };
        [tlv appendBytes:length length:3];
    }

    [tlv appendData:encoded];

    uint8_t terminator = kNdefTerminatorTLV;
    [tlv appendBytes:&terminator length:1];

    return tlv;
}

- (NSData *) data:(NSData *)data paddedToLength:(NSUInteger)length {
    NSMutableData *padded = [NSMutableData dataWithData:data];
    if (padded.length > length) {
        [padded setLength:length];
    } else if (padded.length < length) {
        [padded increaseLengthBy:length - padded.length];    // zero filled
    }
    return padded;
}

- (NSData *) data:(NSData *)data paddedToMultipleOf:(NSUInteger)size {
    if (size == 0 || data.length % size == 0) {
        return data;
    }
    NSUInteger paddedLength = ((data.length / size) + 1) * size;
    return [self data:data paddedToLength:paddedLength];
}

- (NSArray *) uint8ArrayFromNSData:(NSData *) data {
    const uint8_t *bytes = [data bytes];
    NSMutableArray *array = [NSMutableArray arrayWithCapacity:data.length];
    for (NSUInteger i = 0; i < [data length]; i++) {
        [array addObject:[NSNumber numberWithInt:bytes[i]]];
    }
    return array;
}

- (NSData *) uint8ArrayToNSData:(NSArray *) array {
    if (![array isKindOfClass:[NSArray class]]) {
        return [NSData data];
    }
    NSMutableData *data = [[NSMutableData alloc] initWithCapacity: [array count]];
    for (NSNumber *number in array) {
        uint8_t b = (uint8_t)[number unsignedIntValue];
        [data appendBytes:&b length:1];
    }
    return data;
}

- (NSString*) dictionaryAsJSONString:(NSDictionary *)dict {
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dict options:0 error:&error];
    NSString *jsonString;
    if (! jsonData) {
        jsonString = [NSString stringWithFormat:@"Error creating JSON for NDEF Message: %@", error];
        NSLog(@"%@", jsonString);
    } else {
        jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    }
    return jsonString;
}

@end
