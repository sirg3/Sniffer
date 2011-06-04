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


#include "ChunkedBuffer.h"
#include <assert.h>

ChunkedBuffer::ChunkedBuffer(size_t chunkSize) :
	mChunkSize(chunkSize),
	mCurrentOffset(0)
{
	mChunks.push_back(CheckedAlloc(chunkSize));
}

ChunkedBuffer::~ChunkedBuffer()
{
	for (int i = 0; i < mChunks.size(); i++) {
		free(mChunks[i]);
	}
}

void ChunkedBuffer::AppendBytes(const void *bytes, size_t length)
{
	while (length > mChunkSize - mCurrentOffset) {
		// Copy what will fit into the current chunk
		size_t available = mChunkSize - mCurrentOffset;
		memcpy(mChunks.back(), bytes, available);
		
		// Advance past the bytes we just wrote
		bytes = (char *)bytes + available;
		length -= available;
		
		// And add a new chunk to our buffer to hold what's left of this data
		mChunks.push_back(CheckedAlloc(mChunkSize));
		mCurrentOffset = 0;
	}
	
	memcpy(mChunks.back() + mCurrentOffset, bytes, length);
	mCurrentOffset += length;
}

void ChunkedBuffer::CopyBytes(off_t offset, size_t length, void *outBuffer) const
{
	char *resultPtr = (char *)outBuffer;
	
	while (length) {
		int chunk = offset / mChunkSize;
		int readOffset = offset % mChunkSize;
		int readSize = std::min(length, mChunkSize - readOffset);
		
		memcpy(resultPtr, mChunks[chunk] + readOffset, readSize);
		
		offset = 0;
		resultPtr += readSize;
		length -= readSize;
	}
}

size_t ChunkedBuffer::Length() const
{
	return (mChunks.size() - 1) * mChunkSize + mCurrentOffset;
}

char * ChunkedBuffer::CheckedAlloc(size_t size)
{
	char *result = (char *)malloc(size);
	assert(result);
	return result;
}
