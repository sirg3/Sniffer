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

#include <unistd.h>
#include <vector>

/**
 * A memory buffer that can grow to arbitrary sizes without paying the cost of
 * copying all of the data every time the buffer needs to grow. This is achieved
 * by spreading the data across various chunks of memory that are allocated on
 * demand.
 */
class ChunkedBuffer {
public:
	ChunkedBuffer(size_t chunkSize);
	~ChunkedBuffer();
	
	/**
	 * Appends a series of bytes to this memory buffer.
	 *
	 * @param bytes - the bytes to append
	 * @param length - the number of bytes to append
	 */
	void AppendBytes(const void *bytes, size_t length);
	
	/**
	 * The number of bytes that have been added to the buffer.
	 */
	size_t Length() const;
	
	/**
	 * Copies bytes from this buffer into another buffer.
	 *
	 * @param offset - the offset into this buffer
	 * @param length - the number of bytes to copy
	 * @param outBuffer - the buffer to copy into
	 */
	void CopyBytes(off_t offset, size_t length, void *outBuffer) const;
	
private:
	ChunkedBuffer(const ChunkedBuffer &other);
	ChunkedBuffer& operator= (const ChunkedBuffer &other);
	
	static char * CheckedAlloc(size_t size);
	
	size_t mChunkSize;
	off_t mCurrentOffset;
	std::vector<char *> mChunks;
};
