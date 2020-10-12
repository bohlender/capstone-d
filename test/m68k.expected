****************
Platform: M68K
Code: 0x4c 0x00 0x54 0x04 0x48 0xe7 0xe0 0x30 0x4c 0xdf 0x0c 0x07 0xd4 0x40 0x87 0x5a 0x4e 0x71 0x02 0xb4 0xc0 0xde 0xc0 0xde 0x5c 0x00 0x1d 0x80 0x71 0x12 0x01 0x23 0xf2 0x3c 0x44 0x22 0x40 0x49 0x0e 0x56 0x54 0xc5 0xf2 0x3c 0x44 0x00 0x44 0x7a 0x00 0x00 0xf2 0x00 0x0a 0x28 0x4e 0xb9 0x00 0x00 0x00 0x12 0x4e 0x75 
Disasm:
0x1000:	mulu.l	d0, d4:d5
	op_count: 2
	reading from reg: d0
	writing to reg:   d4
	writing to reg:   d5
	groups_count: 0
		operands[0].type: REG = d0
		operands[1].type: REG_PAIR = (d4, d5)

0x1004:	movem.l	d0-d2/a2-a3, -(a7)
	op_count: 2
	reading from reg: d0
	reading from reg: d1
	reading from reg: d2
	reading from reg: a2
	reading from reg: a3
	writing to reg:   a7
	groups_count: 0
		operands[0].type: REG_BITS = $c07
		operands[1].type: MEM
		address mode: Register Indirect - Address with Predecrement

0x1008:	movem.l	(a7)+, d0-d2/a2-a3
	op_count: 2
	writing to reg:   a7
	writing to reg:   d0
	writing to reg:   d1
	writing to reg:   d2
	writing to reg:   a2
	writing to reg:   a3
	groups_count: 0
		operands[0].type: MEM
		address mode: Register Indirect - Address with Postincrement
		operands[1].type: REG_BITS = $c07

0x100c:	add.w	d0, d2
	op_count: 2
	reading from reg: d0
	writing to reg:   d2
	groups_count: 0
		operands[0].type: REG = d0
		operands[1].type: REG = d2

0x100e:	or.w	d3, (a2)+
	op_count: 2
	reading from reg: d3
	writing to reg:   a2
	groups_count: 0
		operands[0].type: REG = d3
		operands[1].type: MEM
		address mode: Register Indirect - Address with Postincrement

0x1010:	nop	
	groups_count: 0

0x1012:	andi.l	#$c0dec0de, (a4, d5.l * 4)
	op_count: 2
	reading from reg: d5
	reading from reg: a4
	groups_count: 0
		operands[0].type: IMM = 0xc0dec0de
		operands[1].type: MEM
			operands[1].mem.base: REG = a4
			operands[1].mem.index: REG = d5
			operands[1].mem.index: size = l
			operands[1].mem.scale: 4
		address mode: Address Register Indirect With Index - Base displacement

0x101a:	move.b	d0, ([a6, d7.w], $123)
	op_count: 2
	reading from reg: d0
	reading from reg: d7
	reading from reg: a6
	groups_count: 0
		operands[0].type: REG = d0
		operands[1].type: MEM
			operands[1].mem.base: REG = a6
			operands[1].mem.index: REG = d7
			operands[1].mem.index: size = w
		address mode: Memory indirect - Preindex

0x1020:	fadd.s	#3.141500, fp0
	op_count: 2
	writing to reg:   fp0
	groups_count: 0
		operands[0].type: FP_SINGLE
			operands[0].simm: 3.141500
		operands[1].type: REG = fp0

0x1028:	scc.b	d5
	op_count: 1
	writing to reg:   d5
	groups_count: 0
		operands[0].type: REG = d5

0x102a:	fmove.s	#1000.000000, fp0
	op_count: 2
	writing to reg:   fp0
	groups_count: 0
		operands[0].type: FP_SINGLE
			operands[0].simm: 1000.000000
		operands[1].type: REG = fp0

0x1032:	fsub	fp2, fp4
	op_count: 2
	reading from reg: fp2
	writing to reg:   fp4
	groups_count: 0
		operands[0].type: REG = fp2
		operands[1].type: REG = fp4

0x1036:	jsr	$12.l
	op_count: 1
	groups_count: 1
		operands[0].type: MEM
		address mode: Absolute Data Addressing  - Long

0x103c:	rts	
	groups_count: 1

0x103e:

