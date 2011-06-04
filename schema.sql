PRAGMA foreign_keys = ON;

CREATE TABLE applications (
	name TEXT,
	path TEXT,
	bookmark BLOB
);

CREATE TABLE packets (
	application_fk INTEGER,
	data_offset INTEGER,
	data_size INTEGER
);

CREATE TABLE metadata (
	packet_fk INTEGER,
	name TEXT,
	data TEXT
);
