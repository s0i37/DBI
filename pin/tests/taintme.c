#include <stdio.h>
#include <stdint.h>

int parse(char *input)
{
	uint8_t a;
	uint8_t b;
	uint16_t c;

	b = (uint8_t)input[3];
	c = ((uint16_t *)input)[0];
	if(c == 0xffff)
		return 1;
	else
		return 0;

	if(b > 0)
	{
		if( b == 0x72 )
		{
			a = b + 0x22;
			a ^= 0x11;
			if( a == c )
				return 3;
			else
				return 2;
		}
		else
			return 1;
	}
	else
		return 0;
}

void main(void)
{
	char input[10];
	gets(&input);
	printf("%d\n", parse(&input));
}