/*
=========================================================================================
AUTHORS

Created by: Rory Pinkney (100207541) and Christopher Fleetwood (100228021)

VERSION HISTORY

v1.0 21/10/18
v1.1 23/10/18
v2.0 30/10/18
v2.1 05/10/18
v2.2 07/10/18

DESCRIPTION
The purpose of this program is to encipher a message stored in a text file by using letter
transpositon based on the length of a private key input by the user. The deciphering of 
the message requires the same private key.

The ARM-v7 code was written to adhere to the AAPCS Procedure Call Standard. Conditional 
operations have been used to reduce the use of short branches to reduce runtime. 

REFERENCES

thinkinggeek.com/arm-assembler-raspberry-pi
ARMv7 Architecture Reference Manual

========================================================================================
*/
.data
.balign 4
message: .skip 250						@250 words so 1000 bytes or characters
output: .skip 250						@250 words 1000 char
index: .skip 100						@100 words 100 int

.text
/*
strlen:	Takes a char* input and counts the characters, returning the count as an integer
r0	(char*)		pointer to a string

strlen pseudocode: 

strlen(char* T) returns int
    int i <- 0
    while (T[i] != null)
        i++

    return i
*/
strlen:
	ldrb r1, [r0]
	mov r2, #0							@set counter to 0
strlen_loop:
	cmp r1, #0
	addne r2, r2, #1					@increment counter 			|	
	ldrneb r1, [r0, #1]!				@load next char in string   |	if char != NULL
	bne strlen_loop						@call loop					|	
	mov r0, r2			
	bx lr

/*
order:	Takes the private key and alpabetises it, returning an array of integers, each indicating 
	an index in the ordered key, these indexes provide the column order to print in. 
	The algorithm we use to accomplish this loops through the private key saving the index of
	the lowest character in the alphabet, it then puts that number in the index array and sets
	the character in the private key to the integer value 255 so that it doesn't intefere with
	the next pass. It does this procedure strlen(key) times each time saving the lowest 
	character's index value in the index array, in 'dragon's case, being {2, 0, 3, 5, 4, 1}.
r0	(char*)		private key
r1	(mem space)	space to store the array of indexes of the ordered key
r2	(int)		strlen of private key string

order pseudocode:

order(char* key, int* index, int keyLen) returns void
    int n <- 0
    while (n < keyLen)
        int cmp1 <- 0
        int cmp2 <- 0
        while (cmp2 != keyLen)
	    cmp++
	    if (key[cmp1] > key[cmp2])
    	        cmp1 <- cmp2

        index[n] <- cmp1
        key[cmp1] <- 255									-highest immediate value in arm assembly
        n++
*/
order:
	push {r4-r8}
	mov r7, #0							@counter to perform procedure strlen(key) times
	mov r8, #255						@register loaded with highest immediate int value
order_loop:
	mov r5, #0							@r5 holds index of first char for cmp 
	mov r6, #0							@r6 holds index of second char for cmp
order_inner_loop:
	add r6, r6, #1						@increment r6 by one so you compare the 1st and 2nd char
	cmp r6, r2							@checking if all the chars have been compared
	beq order_inner_end					@branch on having compared all chars in this iteration
	ldrb r3, [r0, +r5]
	ldrb r4, [r0, +r6]					@load 1st and 2nd char for cmp
	cmp r3, r4
	ble order_inner_loop				@if char1 is lower dont change index and call loop
	mov r5, r6							@found new lowest character, move index into r5
	b order_inner_loop
order_inner_end:
	add r7, r7, #1						@increment counter by one
	str r5, [r1], #4					@store r5 (index of the lowest char in previous pass)
	cmp r7, r2							@compare counter and strlen(key)
	beq order_end						@branches on equal to order_end	
	strb r8, [r0, +r5]					@store #255 in place of the lowest char of previous pass
	b order_loop
order_end:
	pop {r4-r8}
	bx lr

/*
format:	Takes the message string and removes all caps, spaces and other punctuation, then adds x's 
	until the length is a multiple of strlen(key) (r1). There is no mod function in arm so the 
	'mod' loop subtracts strlen(key) from the length of the message with no caps or other chars
	until it's value is less than or equal to zero. If it is less than zero, the absolute value
	of that number is the deficit of characters in the formatted string length, so you need to
	add that number of 'x's.
r0	(*char)		message
r1	(int)		strlen of private key	

format pseudocode:

format(char* message, int keyLen) returns void
    int i <- 0
    inf j <- 0
    while (message[i] != null)
        message[i] |= 32
        if (message[i] < 123 and message[i] > 96)
 	    message[j] <- message[i];
 	    j++
        i++
 
    int n = (j % keyLen) - keyLen							-same as subtracting until under 0 (arm has no mod function)
    while (n != 0)
        message[j] <- 'x'
        j++

    message[j] <- '\0'										-null terminate formatted string
*/
format:
	push {r4, lr}
	mov r2, r0							@copy pointer into r2 so that the string is edited in place
	mov r4, #0
format_loop:
	ldrb r3, [r2], #1					@load r3 with first character in 'message'
	cmp r3, #0							@check if null terminator
	beq mod
	orr r3, r3, #32						@OR function on #32 converts all uppercase to lowercase
	cmp r3, #97							@ |
	blt format_loop						@ |if char not in the alphabet, do not store and do not 
	cmp r3, #122						@ |increment the running total character count.
	bgt format_loop						@ |
	strb r3, [r0], #1					@store character 
	add r4, r4, #1						@increment character count	
	b format_loop	
mod:									@similar to mod function
	sub r4, r4, r1						@subtract strlen(key) from running character count
	cmp r4, #0
	beq cleanup_end						@if equal to 0 then already multiple of strlen(key) so
	bgt mod								@skip adding x's loop altogether.
	mov r3, #120						@set r3 <- ascii value 'x'
cleanup_loop:
	strb r3, [r0], #1					@store 'x'
	add r4, r4, #1						@increment character deficit (negative number)
	cmp r4, #0							@until it hits 0
	bne cleanup_loop
cleanup_end:
	mov r3, #0
	strb r3, [r0]						@null terminate formatted string
	pop {r4, lr}
	bx lr
/*
sort:	To encrypt, use the 'index' array of integers ({2, 0, 3, 5, 4, 1} in 'dragon's case) and
	start with the first integer in that array. Load the character from 'message' with that 
	index value (2) and store it in the 0 index of 'output' (post increment updating by #1) 
	Then increment the index value by strlen(key), in this case making it 8, and check if this
	value is greater than or equal to the strlen(message) (equal to for proper bounds checking 
	because arrays are zero indexed). If it is not, then load and store as before. If it is, 
	then move to the next integer in the 'index' array and continue. Repeat until complete for 
	all values in 'index' array.
	To decrypt, follow the same method except swap the method for loading and storing. That is, 
	take the character at the the 0 index of 'message' and store it in the 'index' integer (plus
	strlen(key)) of the the 'output'.
r0	(char*)		message pointer
r1	(int)		strlen(message)
r2	(int)		strlen(key)
r3	(char)		'0' or '1' indicating encrypt or decrpyt (command line arguments)

sort pseudocode:

sort(char* message, int msgLen, int keyLen, char mode) returns void
    int index <- 0
    int i <- 0
    char output[]
    while (i < keyLen)
	for (int j <- order[i], j < msgLen, j += keyLen)
	    if (mode = '0')									-encrypt
		output[index] <- message[j]
	    else if (mode = '1')							-decrypt
		output[j] <- message[index]

	i++

    output[msgLen] <- '\0'								-null terminate
*/
sort:
	push {r4-r8}
	mov r8, r1
	mov r6, #0							@set counter to 0
	ldr r1, =output
	ldr r4, =index
	ldr r5, [r4], #4					@load first integer in 'index' array
encode_loop:
	cmp r5, r8							@check if current index is greater than strlen(message)
	bge encode_cont						@branch if it is
	cmp r3, #48							@checking if encrpyt or decrypt (ascii value '0')
	ldreqb r7, [r0, r5]
	ldrneb r7, [r0], #1		
	streqb r7, [r1], #1					@conditional execution if encrypt - '0'
	strneb r7, [r1, r5]					@conditional execution if decrypt - '1'
	add r5, r5, r2						@increment current index by strlen(key)
	b encode_loop
encode_cont:	
	ldr r5, [r4], #4					@load next integer in 'index' array
	add r6, r6, #1						@increment counter by one
	cmp r6, r2							@compare counter to strlen(key)
	bne encode_loop
	mov r4, #0							@null terminate 'output'
	strb r4, [r1, r8]
	pop {r4-r8}
	bx lr

/*
read:	Takes the stdin from the cat command line input and loops through the characters, storing
	each one into the 'message' memory space in the heap
r0	(mem space)	space to store the message read in from a text file ('message')

read pseudocode

read(char* message) returns void
    int i <- 0
    while (getchar != EOF)
	message[i] <- getchar
	i++

    message[i] <- '\0'										-null terminate
*/
read:
	push {r4, lr}
	mov r4, r0							@r4 <- memory address, so that getchar doesn't invalidate it 
read_loop:
	bl getchar							@get next character
	cmp r0, #-1							@compare to EOF special getchar character
	beq read_end
	strb r0, [r4], #1					@store in 'message' post increment
	b read_loop
read_end:
	mov r0, #0
	strb r0, [r4]						@null terminate read in string
	pop {r4, lr}
	bx lr

/*
main:	Driver for each of the above functions
r4	(char*)		command line argument for encrypt('0')/decrypt('1')
r5	(char*)		command line argument for private key
r6	(int)		strlen(key)
r7	(int)		strlen(message)
*/
.global main
main:
	push {lr}
	ldr r4, [r1, #4]					@get command line argument for encrypt/decrypt
	ldr r5, [r1, #8]					@get command line argument for private key
	
	mov r0, r5
	bl strlen							@count characters in private key
	mov r6, r0

	ldr r0, =message
	bl read								@read msg.txt

	ldr r0, =message
	mov r1, r6
	bl format							@format read in string

	ldr r0, =message
	bl strlen							@count characters in formatted message
	mov r7, r0

	mov r0, r5
	ldr r1, =index
	mov r2, r6
	bl order							@compute 'index' array for this private key

	ldr r0, =message
	mov r1, r7
	mov r2, r6
	ldrb r3, [r4]
	bl sort								@sort 'message' based on the 'index' array

	ldr r0, =output
	bl printf							@print 'output' (encoded or decoded 'message')

	pop {lr}
	bx lr								@end
