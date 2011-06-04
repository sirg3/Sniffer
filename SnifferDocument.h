// Copyright 2011 Joe Ranieri.
//
// Sniffer is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 2 of the License, or (at your option) any later
// version.
//
// Sniffer is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// Sniffer. If not, see <http://www.gnu.org/licenses/>.

#import <Cocoa/Cocoa.h>
#import <libkern/OSAtomic.h>
#import <sqlite3.h>
#import <pcap.h>
#import "ChunkedBuffer.h"
@class SnifferWindowController;

@interface SnifferDocument : NSDocument {
	OSSpinLock databaseLock;
	sqlite3 *database;
	
	OSSpinLock bufferLock;
	ChunkedBuffer *packetBuffer;

	sqlite3_stmt *appSelectStmt;
	sqlite3_stmt *appInsertStmt;
	sqlite3_stmt *packetInsertStmt;
	sqlite3_stmt *metadataInsertStmt;
	sqlite3_stmt *packetDataSelectStmt;
	
	SnifferWindowController *windowController;
	BOOL isNewDocument;
}

- (BOOL)isNewDocument;

- (sqlite3 *)acquireDatabase;
- (void)releaseDatabase;

- (void)addPacket:(NSData *)data header:(pcap_pkthdr *)header identifier:(NSUInteger)packetID application:(NSString *)application metadata:(NSDictionary *)metadata;

- (NSData *)packetData:(NSUInteger)packetID;

@end


