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

#import "SnifferDocument.h"
#import "SpinLock.h"
#import "SnifferWindowController.h"

// See http://wiki.wireshark.org/Development/LibpcapFileFormat
struct pcap_hdr_t {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
};

struct pcaprec_hdr_t {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
};


@implementation SnifferDocument

- (id)init {
	if (self = [super init]) {
		NSURL *initialSQLURL = [[NSBundle mainBundle] URLForResource:@"schema" withExtension:@"sql"];
		NSString *initialSQL = [NSString stringWithContentsOfURL:initialSQLURL encoding:NSUTF8StringEncoding error:NULL];
		
		sqlite3_open(":memory:", &database);
		sqlite3_exec(database, [initialSQL UTF8String], NULL, NULL, NULL);
		sqlite3_prepare_v2(database, "SELECT rowid FROM applications WHERE path = ?", -1, &appSelectStmt, NULL);
		sqlite3_prepare_v2(database, "INSERT INTO applications (name, path, bookmark) VALUES (?, ?, ?)", -1, &appInsertStmt, NULL);
		sqlite3_prepare_v2(database, "INSERT INTO packets (rowid, application_fk, data_offset, data_size) VALUES (?, ?, ?, ?)", -1, &packetInsertStmt, NULL);
		sqlite3_prepare_v2(database, "INSERT INTO metadata (packet_fk, name, data) VALUES (?, ?, ?)", -1, &metadataInsertStmt, NULL);
		sqlite3_prepare_v2(database, "SELECT data_offset, data_size FROM packets ORDER BY rowid LIMIT 1 OFFSET ?", -1, &packetDataSelectStmt, NULL);

		databaseLock = OS_SPINLOCK_INIT;
		
		// Create our packet buffer with an initial size of 64MB
		packetBuffer = new ChunkedBuffer(67108864);
		
		// Our in-memory buffer is just going to be a pcap file. The overhead for
		// this is pretty small and makes it pretty easy to export as pcap or load
		// from pcap files.
		pcap_hdr_t header;
		header.magic_number = 0xA1B2C3D4; 
		header.version_major = 2;
		header.version_minor = 4;
		header.thiszone = 0;
		header.sigfigs = 0;
		header.snaplen = 65535;
		header.network = 1;
		packetBuffer->AppendBytes(&header, sizeof(header));
		
		bufferLock = OS_SPINLOCK_INIT;
		
		isNewDocument = YES;
	}
	
	return self;
}

- (void)makeWindowControllers {
	windowController = [[SnifferWindowController alloc] initWithWindowNibName:@"SnifferWindowController"];
	[self addWindowController:windowController];
}

#pragma mark -

- (void)addPacket:(NSData *)data header:(pcap_pkthdr *)header identifier:(NSUInteger)packetID application:(NSString *)application metadata:(NSDictionary *)metadata {
	off_t packetOffset;
	
	// Only put code in here that needs the file lock
	{
		SpinLock lock(&bufferLock);
		
		pcaprec_hdr_t headerRec;
		headerRec.ts_sec = header->ts.tv_sec;
		headerRec.ts_usec = header->ts.tv_usec;
		headerRec.incl_len = header->caplen;
		headerRec.orig_len = header->len;
		packetBuffer->AppendBytes(&headerRec, sizeof(headerRec));
		
		packetOffset = packetBuffer->Length();
		packetBuffer->AppendBytes([data bytes], [data length]);
	}
	
	// Only put code in here that needs the database lock
	{
		SpinLock dbLock(&databaseLock);
		
		// First, see if we have already put this application into the applications
		// table. If not, insert it.
		sqlite3_int64 appRowID = -1;
		sqlite3_bind_text(appSelectStmt, 1, [application UTF8String], -1, NULL);
		if (SQLITE_ROW == sqlite3_step(appSelectStmt)) {
			appRowID = sqlite3_column_int64(appSelectStmt, 0);
		} else {
			// FIXME: we might want to bookmark icons too, once we have that bit
			// of UI working.
			NSData *bookmark = [[NSURL fileURLWithPath:application] bookmarkDataWithOptions:0
															 includingResourceValuesForKeys:nil
																			  relativeToURL:nil
																					  error:NULL];
			
			sqlite3_bind_text(appInsertStmt, 1, [[application lastPathComponent] UTF8String], -1, NULL);
			sqlite3_bind_text(appInsertStmt, 2, [application UTF8String], -1, NULL);
			sqlite3_bind_blob(appInsertStmt, 3, [bookmark bytes], [bookmark length], NULL);
			sqlite3_step(appInsertStmt);
			sqlite3_reset(appInsertStmt);
			
			appRowID = sqlite3_last_insert_rowid(database);
		}
		sqlite3_reset(appSelectStmt);
		
		// Now that we have our application inserted, we can insert the packet
		sqlite3_bind_int64(packetInsertStmt, 1, packetID);
		sqlite3_bind_int64(packetInsertStmt, 2, appRowID);
		sqlite3_bind_int64(packetInsertStmt, 3, packetOffset);
		sqlite3_bind_int64(packetInsertStmt, 4, [data length]);
		sqlite3_step(packetInsertStmt);
		sqlite3_reset(packetInsertStmt);
		
		// Now whatever metadata we might have been given
		[metadata enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL *stop) {
			// FIXME: support more types
			assert([key isKindOfClass:[NSString class]]);
			assert([value isKindOfClass:[NSString class]]);
			
			sqlite3_bind_int64(metadataInsertStmt, 1, packetID);
			sqlite3_bind_text(metadataInsertStmt, 2, [key UTF8String], -1, NULL);
			sqlite3_bind_text(metadataInsertStmt, 3, [value UTF8String], -1, NULL);
			sqlite3_step(metadataInsertStmt);
			sqlite3_reset(metadataInsertStmt);
		}];
	}
	
	dispatch_async(dispatch_get_main_queue(), ^(void) {
		[windowController dataChanged];
	});
}

- (NSData *)packetData:(NSUInteger)packetID {
	NSUInteger dataOffset = 0;
	NSUInteger dataSize = 0;
	{
		SpinLock lock(&databaseLock);
		sqlite3_reset(packetDataSelectStmt);
		sqlite3_bind_int64(packetDataSelectStmt, 1, packetID);
		sqlite3_step(packetDataSelectStmt);
		dataOffset = sqlite3_column_int(packetDataSelectStmt, 0);
		dataSize = sqlite3_column_int(packetDataSelectStmt, 1);
	}
	
	NSMutableData *data = [NSMutableData dataWithLength:dataSize];
	{
		SpinLock lock(&bufferLock);
		packetBuffer->CopyBytes(dataOffset, dataSize, [data mutableBytes]);
	}
	
	return data;
}

- (sqlite3 *)acquireDatabase {
	OSSpinLockLock(&databaseLock);
	return database;
}

- (void)releaseDatabase {
	OSSpinLockUnlock(&databaseLock);
}

#pragma mark -

- (NSString *)temporaryFolder {
	NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSBundle mainBundle] bundleIdentifier]];
	BOOL success = [[NSFileManager defaultManager] createDirectoryAtPath:path
											 withIntermediateDirectories:YES
															  attributes:nil
																   error:NULL];
	if (success) {
		return path;
	} else {
		// Hrm, we failed for some reason. Let's just return the temporary directory
		// and hope for the best!
		return NSTemporaryDirectory();
	}
}

- (NSData *)databaseData {
	// Unfortunately SQLite has no way to serialize a database to bytes in memory.
	// Instead, it requires you to write to a file on disk.
	//
	// In the future we could optimize this with one of two strategies:
	// - use named pipes (mkfifo)
	// - implement an SQLite VFS (sqlite3_vfs_register)
	NSData *result = nil;

	NSString *backupPath = [[self temporaryFolder] stringByAppendingPathComponent:@"metadata.sqlite"];
	sqlite3 *diskDB;
	if (SQLITE_OK == sqlite3_open([backupPath fileSystemRepresentation], &diskDB)) {
		SpinLock lock(&databaseLock);
		
		sqlite3_backup *backup = sqlite3_backup_init(diskDB, "main", database, "main");
		if (backup) {
			sqlite3_backup_step(backup, -1);
			sqlite3_backup_finish(backup);
		}
		sqlite3_close(diskDB);
	}
	
	result = [NSData dataWithContentsOfFile:backupPath];
	[[NSFileManager defaultManager] removeFileAtPath:backupPath handler:nil];
	
	return result;
}

- (void)loadDatabaseFromData:(NSData *)data {
	// Unfortunately SQLite has no way to read a database from memory. Instead,
	// it requires you to read the file from disk.
	//
	// In the future we could optimize this with one of two strategies:
	// - use named pipes (mkfifo)
	// - implement an SQLite VFS (sqlite3_vfs_register)
	
	NSString *backupPath = [[self temporaryFolder] stringByAppendingPathComponent:@"metadata.sqlite"];
	[data writeToFile:backupPath atomically:NO];
	
	sqlite3 *diskDB;
	if (SQLITE_OK == sqlite3_open([backupPath fileSystemRepresentation], &diskDB)) {
		SpinLock lock(&databaseLock);
		
		sqlite3_backup *backup = sqlite3_backup_init(database, "main", diskDB, "main");
		if (backup) {
			sqlite3_backup_step(backup, -1);
			sqlite3_backup_finish(backup);
		}
		sqlite3_close(diskDB);
	}
	
	[[NSFileManager defaultManager] removeFileAtPath:backupPath handler:nil];
}

- (NSFileWrapper *)fileWrapperOfType:(NSString *)typeName error:(NSError **)outError {
	NSFileWrapper *result = [[[NSFileWrapper alloc] initDirectoryWithFileWrappers:nil] autorelease];
	[result addRegularFileWithContents:[self databaseData] preferredFilename:@"metadata.sqlite"];
	
	// Copy all the data out of our packet buffer
	NSMutableData *data;
	{
		SpinLock lock(&bufferLock);
		data = [NSMutableData dataWithLength:packetBuffer->Length()];
		packetBuffer->CopyBytes(0, packetBuffer->Length(), [data mutableBytes]);
	}
	[result addRegularFileWithContents:data preferredFilename:@"packets.pcap"];
	
	return result;
}

- (BOOL)readFromFileWrapper:(NSFileWrapper *)fileWrapper ofType:(NSString *)typeName error:(NSError **)outError {
	NSDictionary *wrappers = [fileWrapper fileWrappers];
	NSData *data = [[wrappers objectForKey:@"packets.pcap"] regularFileContents];
	
	// FIXME: we should be doing endian swapping
	if (*(uint32_t *)[data bytes] != 0xA1B2C3D4) {
		return NO;
	}
	
	packetBuffer->AppendBytes([data bytes], [data length]);
	
	[self loadDatabaseFromData:[[wrappers objectForKey:@"metadata.sqlite"] regularFileContents]];
	isNewDocument = NO;
	
	return YES;
}

- (BOOL)isNewDocument {
	return isNewDocument;
}

@end
