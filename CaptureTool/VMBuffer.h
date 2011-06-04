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

#include <mach/mach.h>

/**
 * A buffer of memory requested from the kernel. This is guaranteed to be page
 * aligned, but cannot be shrunk.
 */
template<class T>
class VMBuffer {
public:
	VMBuffer(size_t initialSize = PAGE_SIZE) {
		Grow(initialSize);
	}
	
	~VMBuffer() {
		vm_deallocate(mach_task_self(), mData, mSize);
	}
	
	/**
	 * Expands the buffer to contain at least `newSize` bytes.
	 *
	 * This function has several side effects and limitations:
	 * - the existing data pointer will be invalidated
	 * - the new buffer is not guaranteed to be zeroed
	 * - data will not be copied from the old buffer
	 *
	 * @param newSize The number of bytes the buffer needs to hold.
	 */
	void Grow(size_t newSize) {
		if (mSize >= newSize) return;
		
		if (mData)
			vm_deallocate(mach_task_self(), mData, mSize);
		
		// Make sure that the requested amount of memory is page aligned.
		newSize += newSize % PAGE_SIZE;
		
		if (vm_allocate(mach_task_self(), &mData, newSize, VM_FLAGS_ANYWHERE) == 0) {
			mSize = newSize;
		} else {
			assert(0);
		}
	}
	
	T& operator[] (off_t offset) {
		assert(offset * sizeof(T) < mSize);
		return reinterpret_cast<T *>(mData)[offset];
	}
	
	/**
	 * The allocated size of the buffer. This may be larger than the size requested
	 * by Grow().
	 */
	size_t Size() const {
		return mSize;
	}
	
	/**
	 * The underlying data pointer.
	 */
	T * Data() {
		return reinterpret_cast<T *>(mData);
	}

private:
	vm_size_t mSize;
	vm_address_t mData;
};

