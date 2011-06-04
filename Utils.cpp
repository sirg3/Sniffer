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

#include "Utils.h"
#include <pthread.h>
#include <Block.h>

static void * ThreadEntrypoint(void *info) {
	dispatch_block_t block = (dispatch_block_t)info;
	block();
	
	// We had to create a copy of the block to pass it into pthread_create, so
	// be sure to release it here.
	Block_release(block);
	return NULL;
}

void RunBlockThreaded(dispatch_block_t block) {
	pthread_t result;
	pthread_attr_t attr;
	pthread_attr_init( &attr );
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED );
	pthread_create( &result, &attr, ThreadEntrypoint, Block_copy(block));
	pthread_attr_destroy( &attr );
}
