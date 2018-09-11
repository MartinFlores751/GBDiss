#include <stdio.h>
#include <malloc.h>

int disassembleGB(unsigned char* buffer, int pc);
unsigned char* fileToBuff(char* filename, int *bufsize);

int main(int argc, char **argv)
{
	if(argc == 2)
	{
		int bufsize;
		unsigned char* buffer = fileToBuff(argv[1], &bufsize);
		if(buffer == NULL)
			return -1;
		int pc = 0;
		while(pc < bufsize)
		{
			pc += disassembleGB(buffer, pc);
		}
		
		free(buffer);
		return 0;
	}
	else
		fputs("Pass only one filename as an argument please.\n", stderr);
	return -1;
}

int disassembleGB(unsigned char *buffer, int pc)
{
	unsigned char *code = &buffer[pc];
	int opbytes = 1;
	printf("%04x ", pc);
	switch(*code)
	{
		case 0x00: printf("NOP\n"); break;
		case 0x01: printf("LD BC, #$%02x%02x\n", code[2], code[1]); opbytes = 3; break;
		case 0x02: printf("LD (BC), A\n"); break;
		case 0x03: printf("INC BC\n"); break;
		case 0x04: printf("INC B\n"); break;
		case 0x05: printf("DEC B\n"); break;
		case 0x06: printf("LD B, #$%02x\n", code[1]); opbytes = 2; break;
		case 0x07: printf("RLCA\n"); break;
		case 0x08: printf("LD (#$%02x%02x), SP\n", code[2], code[1]); opbytes = 3; break;
		case 0x09: printf("ADD HL, BC\n"); break;
		case 0x0A: printf("LD A, (BC)\n"); break;
		case 0x0B: printf("DEC BC\n"); break;
		case 0x0C: printf("INC C\n"); break;
		case 0x0D: printf("DEC C\n"); break;
		case 0x0E: printf("LD C, #$%02x\n", code[1]); opbytes = 2; break;
		case 0x0F: printf("RRCA\n"); break;
		case 0x10: printf("STOP\n"); break; /* Problem with this opcode is that it can be 0x10 followed by 0x00 or just 0x10...  */
		case 0x11: printf("LD DE, #$%02x%02x\n", code[2], code[1]); opbytes = 3; break;
		case 0x12: printf("LD (DE), A\n"); break;
		case 0x13: printf("INC DE\n"); break;
		case 0x14: printf("INC D\n"); break;
		case 0x15: printf("DEC D\n"); break;
		case 0x16: printf("LD D, #$%02x\n", code[1]); opbytes = 2; break;
		case 0x17: printf("RLA\n"); break;
		case 0x18: printf("JR #$%04x\n", (pc + (char)code[1])); opbytes = 2; break;
		case 0x19: printf("ADD HL, DE\n"); break;
		case 0x1A: printf("LD A, (DE)\n"); break;
		case 0x1B: printf("DEC DE\n"); break;
		case 0x1C: printf("INC E\n"); break;
		case 0x1D: printf("DEC E\n"); break;
		case 0x1E: printf("LD E, #$%02x\n", code[1]); opbytes = 2; break;
		case 0x1F: printf("RRA\n"); break;
		case 0x20: printf("JR NZ, #$%04x\n", (pc + (char)code[1])); opbytes = 2; break;
		case 0x21: printf("LD HL, #$%02x%02x\n", code[2], code[1]); opbytes = 3; break;
		case 0x22: printf("LD (HL+), A\n"); break;
		case 0x23: printf("INC HL\n"); break;
		case 0x24: printf("INC H\n"); break;
		case 0x25: printf("DEC H\n"); break;
		case 0x26: printf("LD H, #$%02x\n", code [1]); opbytes = 2; break;
		case 0x27: printf("DAA\n"); break;
		case 0x28: printf("JR Z, #$%04x\n", (pc + (char)code[1])); opbytes = 2; break;
		case 0x29: printf("ADD HL, HL\n"); break;
		case 0x2A: printf("LD A,(HL+)\n"); break;
		case 0x2B: printf("DEC HL\n"); break;
		case 0x2C: printf("INC L\n"); break;
		case 0x2D: printf("DEC L\n"); break;
		case 0x2E: printf("LD L, #$%02x\n", code[1]); opbytes = 2; break;
		case 0x2F: printf("CPL"); break;
		case 0x30: printf("JR NC, #$%04x\n", (pc + (char)code[1])); opbytes = 2; break;
		case 0x31: printf("LD SP, #$%02x%02x\n", code[2], code[1]); opbytes = 3; break;
		case 0x32: printf("LD (HL-), A\n"); break;
		case 0x33: printf("INC SP\n"); break;
		case 0x34: printf("INC (HL)\n"); break;
		case 0x35: printf("DEC (HL)\n"); break;
		case 0x36: printf("LD (HL), #$%02x\n", code[1]); opbytes = 2; break;
		case 0x37: printf("SCF\n"); break;
		case 0x38: printf("JR C, #$%04x\n", (pc + (char)code[1])); opbytes = 2; break;
		case 0x39: printf("ADD HL, SP\n"); break;
		case 0x3A: printf("LD A, (HL-)\n"); break;
		case 0x3B: printf("DEC SP\n"); break;
		case 0x3C: printf("INC A\n"); break;
		case 0x3D: printf("DEC A\n"); break;
		case 0x3E: printf("LD A, #$%02x\n", code[1]); opbytes = 2; break;
		case 0x3F: printf("CCF\n"); break;
		case 0x40: printf("LD B, B\n"); break;
		case 0x41: printf("LD B, C\n"); break;
		case 0x42: printf("LD B, D\n"); break;
		case 0x43: printf("LD B, E\n"); break;
		case 0x44: printf("LD B, H\n"); break;
		case 0x45: printf("LD B, L\n"); break;
		case 0x46: printf("LD B, (HL)\n"); break;
		case 0x47: printf("LD B, A\n"); break;
		case 0x48: printf("LD C, B\n"); break;
		case 0x49: printf("LD C, C\n"); break;
		case 0x4A: printf("LD C, D\n"); break;
		case 0x4B: printf("LD C, E\n"); break;
		case 0x4C: printf("LD C, H\n"); break;
		case 0x4D: printf("LD C, L\n"); break;
		case 0x4E: printf("LD C, (HL)\n"); break;
		case 0x4F: printf("LD C, A\n"); break;
		case 0x50: printf("LD D, B\n"); break;
		case 0x51: printf("LD D, C\n"); break;
		case 0x52: printf("LD D, D\n"); break;
		case 0x53: printf("LD D, E\n"); break;
		case 0x54: printf("LD D, H\n"); break;
		case 0x55: printf("LD D, L\n"); break;
		case 0x56: printf("LD D, (HL)\n"); break;
		case 0x57: printf("LD D, A\n"); break;
		case 0x58: printf("LD E, B\n"); break;
		case 0x59: printf("LD E, C\n"); break;
		case 0x5A: printf("LD E, D\n"); break;
		case 0x5B: printf("LD E, E\n"); break;
		case 0x5C: printf("LD E, H\n"); break;
		case 0x5D: printf("LD E, L\n"); break;
		case 0x5E: printf("LD E, (HL)\n"); break;
		case 0x5F: printf("LD E, A\n"); break;
		case 0x60: printf("LD H, B\n"); break;
		case 0x61: printf("LD H, C\n"); break;
		case 0x62: printf("LD H, D\n"); break;
		case 0x63: printf("LD H, E\n"); break;
		case 0x64: printf("LD H, H\n"); break;
		case 0x65: printf("LD H, L\n"); break;
		case 0x66: printf("LD H, (HL)\n"); break;
		case 0x67: printf("LD H, A\n"); break;
		case 0x68: printf("LD L, B\n"); break;
		case 0x69: printf("LD L, C\n"); break;
		case 0x6A: printf("LD L, D\n"); break;
		case 0x6B: printf("LD L, E\n"); break;
		case 0x6C: printf("LD L, H\n"); break;
		case 0x6D: printf("LD L, L\n"); break;
		case 0x6E: printf("LD L, (HL)\n"); break;
		case 0x6F: printf("LD L, A\n"); break;
		case 0x70: printf("LD (HL), B\n"); break;
		case 0x71: printf("LD (HL), C\n"); break;
		case 0x72: printf("LD (HL), D\n"); break;
		case 0x73: printf("LD (HL), E\n"); break;
		case 0x74: printf("LD (HL), H\n"); break;
		case 0x75: printf("LD (HL), L\n"); break;
		case 0x76: printf("HALT\n"); break;
		case 0x77: printf("LD (HL), A\n"); break;
		case 0x78: printf("LD A, B\n"); break;
		case 0x79: printf("LD A, C\n"); break;
		case 0x7A: printf("LD A, D\n"); break;
		case 0x7B: printf("LD A, E\n"); break;
		case 0x7C: printf("LD A, H\n"); break;
		case 0x7D: printf("LD A, L\n"); break;
		case 0x7E: printf("LD A, (HL)\n"); break;
		case 0x7F: printf("LD A, A\n"); break;
		case 0x80: printf("ADD A, B\n"); break;
		case 0x81: printf("ADD A, C\n"); break;
		case 0x82: printf("ADD A, D\n"); break;
		case 0x83: printf("ADD A, E\n"); break;
		case 0x84: printf("ADD A, H\n"); break;
		case 0x85: printf("ADD A, L\n"); break;
		case 0x86: printf("ADD A, (HL)\n"); break;
		case 0x87: printf("ADD A, A\n"); break;
		case 0x88: printf("ADC A, B\n"); break;
		case 0x89: printf("ADC A, C\n"); break;
		case 0x8A: printf("ADC A, D\n"); break;
		case 0x8B: printf("ADC A, E\n"); break;
		case 0x8C: printf("ADC A, H\n"); break;
		case 0x8D: printf("ADC A, L\n"); break;
		case 0x8E: printf("ADC A, (HL)\n"); break;
		case 0x8F: printf("ADC A, A\n"); break;
		case 0x90: printf("SUB B\n"); break;
		case 0x91: printf("SUB C\n"); break;
		case 0x92: printf("SUB D\n"); break;
		case 0x93: printf("SUB E\n"); break;
		case 0x94: printf("SUB H\n"); break;
		case 0x95: printf("SUB L\n"); break;
		case 0x96: printf("SUB (HL)\n"); break;
		case 0x97: printf("SUB A\n"); break;
		case 0x98: printf("SBC A, B\n"); break;
		case 0x99: printf("SBC A, C\n"); break;
		case 0x9A: printf("SBC A, D\n"); break;
		case 0x9B: printf("SBC A, E\n"); break;
		case 0x9C: printf("SBC A, H\n"); break;
		case 0x9D: printf("SBC A, L\n"); break;
		case 0x9E: printf("SBC A, (HL)\n"); break;
		case 0x9F: printf("SBC A, A\n"); break;
		case 0xA0: printf("AND B\n"); break;
		case 0xA1: printf("AND C\n"); break;
		case 0xA2: printf("AND D\n"); break;
		case 0xA3: printf("AND E\n"); break;
		case 0xA4: printf("AND H\n"); break;
		case 0xA5: printf("AND L\n"); break;
		case 0xA6: printf("AND (HL)\n"); break;
		case 0xA7: printf("AND A\n"); break;
		case 0xA8: printf("XOR B\n"); break;
		case 0xA9: printf("XOR C\n"); break;
		case 0xAA: printf("XOR D\n"); break;
		case 0xAB: printf("XOR E\n"); break;
		case 0xAC: printf("XOR H\n"); break;
		case 0xAD: printf("XOR L\n"); break;
		case 0xAE: printf("XOR (HL)\n"); break;
		case 0xAF: printf("XOR A\n"); break;
		case 0xB0: printf("OR B\n"); break;
		case 0xB1: printf("OR C\n"); break;
		case 0xB2: printf("OR D\n"); break;
		case 0xB3: printf("OR E\n"); break;
		case 0xB4: printf("OR H\n"); break;
		case 0xB5: printf("OR L\n"); break;
		case 0xB6: printf("OR (HL)\n"); break;
		case 0xB7: printf("OR A\n"); break;
		case 0xB8: printf("CP B\n"); break;
		case 0xB9: printf("CP C\n"); break;
		case 0xBA: printf("CP D\n"); break;
		case 0xBB: printf("CP E\n"); break;
		case 0xBC: printf("CP H\n"); break;
		case 0xBD: printf("CP L\n"); break;
		case 0xBE: printf("CP (HL)\n"); break;
		case 0xBF: printf("CP A\n"); break;
		case 0xC0: printf("RET NZ\n"); break;
		case 0xC1: printf("POP BC\n"); break;
		case 0xC2: printf("JP NZ, #$%02x%02x\n", code[2], code [1]); opbytes = 3; break;
		case 0xC3: printf("JP #$%02x%02x\n", code[2], code[1]); opbytes = 3; break;
		case 0xC4: printf("CALL NZ, #$%02x%02x\n", code[2], code[1]); opbytes = 3; break;
		case 0xC5: printf("PUSH BC\n"); break;
		case 0xC6: printf("ADD A, #$%02x\n", code[1]); opbytes = 2; break;
		case 0xC7: printf("RST #$00\n"); break;
		case 0xC8: printf("RET Z\n"); break;
		case 0xC9: printf("RET\n"); break;
		case 0xCA: printf("JP Z, #$%02x%02x\n", code[2], code[1]); opbytes = 3; break;
		case 0xCB: printf("PREFIX CB\n"); opbytes = 3; break; opbytes = 3;					// TODO: Implement all Prefix CB Codes
		case 0xCC: printf("CALL Z, #$%02x%02x\n", code[2], code[1]); opbytes = 3; break;
		case 0xCD: printf("CALL #$%02x%02x\n", code[2], code[1]); opbytes = 3; break;
		case 0xCE: printf("ADC A, #$%02x\n", code[1]); opbytes = 2; break;
		case 0xCF: printf("RST #$08\n"); break;
		case 0xD0: printf("RET NC\n"); break;
		case 0xD1: printf("POP DE\n"); break;
		case 0xD2: printf("JP NC, #$%02x%02x\n", code[2], code[1]); opbytes = 3; break;
		case 0xD3: printf("NO CODE\n"); break;
		case 0xD4: printf("CALL NC, #$%02x%02x\n", code[2], code[1]); opbytes = 3; break;
		case 0xD5: printf("PUSH DE\n"); break;
		case 0xD6: printf("SUB #$%02x\n", code[1]); opbytes = 2; break;
		case 0xD7: printf("RST #$10\n"); break;
		case 0xD8: printf("RET C\n"); break;
		case 0xD9: printf("RETI\n"); break;
		case 0xDA: printf("JP C, #$%02x%02x\n", code[2], code[1]); opbytes = 3; break;
		case 0xDB: printf("NO CODE\n"); break;
		case 0xDC: printf("CALL C, #$%02x%02x\n", code[2], code[1]); opbytes = 3; break;
		case 0xDD: printf("NO CODE\n"); break;
		case 0xDE: printf("SBC A, #$%02x\n", code[1]); opbytes = 2; break;
		case 0xDF: printf("RST #$18\n"); break;
		case 0xE0: printf("LDH (#$%04x), A\n", 0xFF00 + code[1]); opbytes = 2; break;
		case 0xE1: printf("POP HL\n"); break;
		case 0xE2: printf("LD (C), A\n"); opbytes = 2; break;
		case 0xE3:
		case 0xE4: printf("NO CODE\n"); break;
		case 0xE5: printf("PUSH HL\n"); break;
		case 0xE6: printf("AND #$%02x\n", code[1]); opbytes = 2; break;
		case 0xE7: printf("RST #$20\n"); break;
		case 0xE8: printf("ADD SP, #$%04x\n", (pc + (char)code[1])); opbytes = 2; break;
		case 0xE9: printf("JP (HL)\n"); break;
		case 0xEA: printf("LD (#$%02x%02x), A\n", code[2], code[1]); opbytes = 3; break;
		case 0xEB: 
		case 0xEC: 
		case 0xED: printf("NO CODE\n"); break;
		case 0xEE: printf("XOR %02x\n", code[1]); opbytes = 2; break;
		case 0xEF: printf("RST #$28\n"); break;
		case 0xF0: printf("LDH A, (#$%04x)\n", 0xFF00 + code[1]); opbytes = 2; break;
		case 0xF1: printf("POP AF\n"); break;
		case 0xF2: printf("LD A, (C)\n"); opbytes = 2; break;
		case 0xF3: printf("DI\n"); break;
		case 0xF4: printf("NO CODE\n"); break;
		case 0xF5: printf("PUSH AF\n"); break;
		case 0xF6: printf("OR #$%02x\n", code[1]); opbytes = 2; break;
		case 0xF7: printf("RST #$30\n"); break;
		case 0xF8: printf("LD HL, #$%04x\n", (pc + (char)code[1])); opbytes = 2; break;
		case 0xF9: printf("LD SP, HL\n"); break;
		case 0xFA: printf("LD A, (#$%02x%02x)\n", code[2], code[1]); opbytes = 3; break;
		case 0xFB: printf("EI\n"); break;
		case 0xFC: 
		case 0xFD: printf("NO CODE\n"); break;
		case 0xFE: printf("CP #$%02x\n", code[1]); opbytes = 2; break;
		case 0xFF: printf("RST #$38\n"); break;
		default: printf("Opcode unknown/not implemented!\n");
	}
	return opbytes;
}



unsigned char* fileToBuff(char* filename, int *bufsize)
{
	// Check the file exists
	FILE *gbRom = fopen(filename, "rb");
	if(gbRom == NULL)
	{
		fprintf(stderr, "File %s could not be opened!\n", filename);
		return NULL;
	}

	// Put file into buffer
	unsigned char* bufferT = NULL;
	if(fseek(gbRom, 0L, SEEK_END) == 0)
	{
		*bufsize = ftell(gbRom);
		if(*bufsize == -1)
			return NULL;

		bufferT = malloc(sizeof(char) * (*bufsize + 1));

		if(fseek(gbRom, 0L, SEEK_SET) != 0)
			return NULL;

		size_t newLen = fread(bufferT, sizeof(char), *bufsize, gbRom);
		if( ferror(gbRom) != 0)
			fputs("Error reading file\n", stderr);
		else
			bufferT[newLen++] = '\0';
		fclose(gbRom);
	}	
	return bufferT;
}
