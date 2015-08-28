/* 
 * Copyright (c) Xeon
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define COPYRIGHT "Copyright (c) Xeon"

typedef int bool;
#define true 1
#define false 0

#define HI_NIBBLE(b) (((b) >> 4) & 0xF)
#define LO_NIBBLE(b) ((b) & 0xF)

void int2binary(bool *bits, int n){

	int b = 0, c = 0;

	for (c = 7; c >= 0; c--){
		if ((n >> c) & 0x1) bits[b++] = 1;
		else bits[b++] = 0;
	}
	return;
}

void long2binary(bool *bits, long n){

	int b = 0, c = 0;

	for (c = 15; c >= 0; c--){
		if ((n >> c) & 0x1) bits[b++] = 1;
		else bits[b++] = 0;
	}
	return;
}

unsigned char hex2bcd (unsigned char x)
{
    unsigned char y;
    y = (x / 10) << 4;
    y = y | (x % 10);
    return y;
}

void hexdump(unsigned char *data, unsigned int size)
{
	unsigned int i;
	printf("\n");
	for(i = 0; i < size; i++)
	{
		printf("%02x", data[i]);
		if(size >= 16 && (i+1) % 2  == 0)
			printf(" ");
		if(size >= 32 && (i+1) % 16  == 0)
			printf("\n");
		if(size == 20 && (i+1) % 10  == 0)
			printf("\n");
	}
	printf("(%d bytes)\n", size);
	return;
}

void *error_checked_malloc(unsigned int size)
{
	int *ptr;
	ptr = malloc(size);
	if (ptr == NULL) {
		fprintf(stderr, "*Memory could not be allocated on the heap.\n");
		exit(-1);
	}
	return ptr;
}
