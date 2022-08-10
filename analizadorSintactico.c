#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define MAX_CAD 132
#define MAX_SIMB 256
#define MAX_MEM 8192
#define MODO_LECTURA "r"
#define MODO_ESCRITURA_BINARIA "wb"
#define FIN_CAD '\0'

typedef char cadena_t[MAX_CAD];
typedef enum
{
    SQR,
    CONST,
    VAR,
    PROCEDURE,
    CALL,
    BEGIN,
    END,
    IF,
    THEN,
    WHILE,
    DO,
    READLN,
    WRITE,
    WRITELN,
    ODD, // Reservadas
    IDENT,
    NUMERO,
    CADENA,
    FINARCH,
    ASIGNACION,
    IGUAL,
    DISTINTO,
    MENOR,
    MENORIGUAL,
    MAYOR,
    MAYORIGUAL,
    MAS,
    MENOS,
    MULTIPLICACION,
    DIVISION,
    PUNTO,
    COMA,
    PUNTOYCOMA,
    ABREPARENTESIS,
    CIERRAPARENTESIS,
    NULO
} simbolo_t;
typedef struct
{
    cadena_t nombre;
    simbolo_t tipo;
    int valor;
} ident_t;
typedef ident_t tabla_t[MAX_SIMB];
typedef unsigned char vector_t[MAX_MEM];

void mensajeErr(FILE *f, int i, cadena_t c);

void programa(FILE *, cadena_t, simbolo_t *, cadena_t, int *, tabla_t);
void bloque(FILE *, cadena_t, simbolo_t *, cadena_t, int *, tabla_t, int, int *, vector_t, int *);
void proposicion(FILE *, cadena_t, simbolo_t *, cadena_t, int *, tabla_t, int, int, int *, vector_t);
void condicion(FILE *, cadena_t, simbolo_t *, cadena_t, int *, tabla_t, int, int, int *, vector_t);
void expresion(FILE *, cadena_t, simbolo_t *, cadena_t, int *, tabla_t, int, int, int *, vector_t);
void termino(FILE *, cadena_t, simbolo_t *, cadena_t, int *, tabla_t, int, int, int *, vector_t);
void factor(FILE *, cadena_t, simbolo_t *, cadena_t, int *, tabla_t, int, int, int *, vector_t);
int busqueda(tabla_t, int, int, cadena_t);
void cargarByte(unsigned char, vector_t, int *);
void cargarInt(int, vector_t, int *);
void cargarIntEn(int, vector_t, int);
void consumirChar(cadena_t);
void aMayuscula(cadena_t);
void escanear(FILE *, cadena_t, simbolo_t *, cadena_t, int *);
void imprimirSimbolo(simbolo_t, cadena_t);

int main(int argc, char *argv[])
{
    cadena_t nombreArchivo;
    cadena_t cadenaSimbolo;
    cadena_t restante;
    simbolo_t simbolo;
    tabla_t tablaSimb;

    FILE *f;

    restante[0] = FIN_CAD;

    if (argc != 2)
    {
        printf("Ingresar el nombre del archivo para realizar un an%clisis l%cxico: ", 160, 130);
        gets(nombreArchivo);
        if ((f = fopen(nombreArchivo, MODO_LECTURA)) == NULL)
        {
            printf("No se pudo leer el archivo\n");
            return 1;
        }
    }
    else
    {
        if ((f = fopen(argv[1], MODO_LECTURA)) == NULL)
        {
            printf("No se pudo leer el archivo\n");
            return 1;
        }
    }

    int contadorRenglon = 1;

    escanear(f, restante, &simbolo, cadenaSimbolo, &contadorRenglon);
    programa(f, restante, &simbolo, cadenaSimbolo, &contadorRenglon, tablaSimb);
    if (simbolo == FINARCH)
    {
        mensajeErr(f, 0, cadenaSimbolo);
    }
    else
    {
        mensajeErr(f, 1, cadenaSimbolo);
    }

    /* do
    {
        escanear(f, restante, &simbolo, cadenaSimbolo, &contadorRenglon);
        imprimirSimbolo(simbolo, cadenaSimbolo);
    } while (simbolo != FINARCH); */

    return 0;
}

void mensajeErr(FILE *f, int i, cadena_t c)
{
    switch (i)
    {
    case 0:
        /* printf("Compilacion exitosa\n"); */
        break;

    case 1:
        printf("ERROR: Se encontro %s despues del programa", c);
        break;

    case 2:
        printf("ERROR: Se esperaba un punto. Se leyo %s", c);
        break;

    case 3:
        printf("ERROR: Se esperaba un identificador. Se leyo %s", c);
        break;

    case 4:
        printf("ERROR: Se esperaba un igual. Se leyo %s", c);
        break;

    case 5:
        printf("ERROR: Se esperaba un numero. Se leyo %s\n", c);
        break;

    case 6:
        printf("ERROR: Se esperaba un punto y coma o una coma. Se leyo %s\n", c);
        break;
    case 7:
        printf("ERROR: Se esperaba un punto y coma. Se leyo %s\n", c);
        break;
    case 8:
        printf("ERROR: Se esperaba una asignacion. Se leyo %s\n", c);
        break;
    case 9:
        printf("ERROR: Se esperaba un operador realcional. Se leyo %s\n", c);
        break;
    case 10:
        printf("ERROR: Se esperaba un identificador, numero, abrir parentesis o cadena. Se leyo %s\n", c);
        break;
    case 11:
        printf("ERROR: Se esperaba cerrar parentesis. Se leyo %s\n", c);
        break;
    case 12:
        printf("ERROR: Se esperaba un punto y coma o end. Se leyo %s\n", c);
        break;
    case 13:
        printf("ERROR: Se esperaba un then. Se leyo %s\n", c);
        break;
    case 14:
        printf("ERROR: Se esperaba un do. Se leyo %s\n", c);
        break;
    case 15:
        printf("ERROR: Se esperaba abrir parentesis. Se leyo %s\n", c);
        break;
    case 16:
        printf("ERROR: Se esperaba cerrar parentesis o coma. Se leyo %s\n", c);
        break;
    case 17:
        printf("ERROR: Identificador duplicado: %s\n", c);
        break;
    case 18:
        printf("ERROR: Identificador no declarado: %s\n", c);
        break;
    case 19:
        printf("ERROR: Se esperaba una variable. Se leyo %s\n", c);
        break;
    case 20:
        printf("ERROR: Se esperaba una variable o constante. Se leyo %s\n", c);
        break;
    case 21:
        printf("ERROR: Se esperaba un procedure. Se leyo %s\n", c);
        break;
    default:
        break;
    }
    fclose(f);

    exit(0);
}

/**/
void programa(FILE *f, cadena_t restante, simbolo_t *simbolo, cadena_t cadenaSimbolo, int *contadorRenglon, tabla_t tablaSimb)
{
    FILE *fb = fopen("a.exe", MODO_ESCRITURA_BINARIA); // arreglar nombre del archivo fuente con nueva extension exe
    vector_t memoria;
    int topeMemoria;
    int contadorVars = 0;

    /* MS-DOS COMPATIBLE HEADER */
    memoria[0] = 0x4D;  // 'M' (Magic number)
    memoria[1] = 0x5A;  // 'Z'
    memoria[2] = 0x60;  // Bytes on last block
    memoria[3] = 0x01;  // (1 bl. = 512 bytes)
    memoria[4] = 0x01;  // Number of blocks
    memoria[5] = 0x00;  // in the EXE file
    memoria[6] = 0x00;  // Number of rememoria[7] = 0x00; // location entries
    memoria[8] = 0x04;  // Size of header
    memoria[9] = 0x00;  // (x 16 bytes)
    memoria[10] = 0x00; // Minimum extra
    memoria[11] = 0x00; // paragraphs needed
    memoria[12] = 0xFF; // Maximum extra
    memoria[13] = 0xFF; // paragraphs needed
    memoria[14] = 0x00; // Initial (relative)
    memoria[15] = 0x00; // SS value
    memoria[16] = 0x60; // Initial SP value
    memoria[17] = 0x01;
    memoria[18] = 0x00; // Checksum
    memoria[19] = 0x00;
    memoria[20] = 0x00; // Initial IP value
    memoria[21] = 0x00;
    memoria[22] = 0x00; // Initial (relative)
    memoria[23] = 0x00; // CS value
    memoria[24] = 0x40; // Offset of the 1st
    memoria[25] = 0x00; // relocation item
    memoria[26] = 0x00; // Overlay number.
    memoria[27] = 0x00; // (0 = main program)
    memoria[28] = 0x00; // Reserved word
    memoria[29] = 0x00;
    memoria[30] = 0x00; // Reserved word
    memoria[31] = 0x00;
    memoria[32] = 0x00; // Reserved word
    memoria[33] = 0x00;
    memoria[34] = 0x00; // Reserved word
    memoria[35] = 0x00;
    memoria[36] = 0x00; // OEM identifier
    memoria[37] = 0x00;
    memoria[38] = 0x00; // OEM information
    memoria[39] = 0x00;
    memoria[40] = 0x00; // Reserved word
    memoria[41] = 0x00;
    memoria[42] = 0x00; // Reserved word
    memoria[43] = 0x00;
    memoria[44] = 0x00; // Reserved word
    memoria[45] = 0x00;
    memoria[46] = 0x00; // Reserved word
    memoria[47] = 0x00;
    memoria[48] = 0x00; // Reserved word
    memoria[49] = 0x00;
    memoria[50] = 0x00; // Reserved word
    memoria[51] = 0x00;
    memoria[52] = 0x00; // Reserved word
    memoria[53] = 0x00;
    memoria[54] = 0x00; // Reserved word
    memoria[55] = 0x00;
    memoria[56] = 0x00; // Reserved word
    memoria[57] = 0x00;
    memoria[58] = 0x00; // Reserved word
    memoria[59] = 0x00;
    memoria[60] = 0xA0; // Start of the COFF
    memoria[61] = 0x00; // header
    memoria[62] = 0x00;
    memoria[63] = 0x00;
    memoria[64] = 0x0E; // PUSH CS
    memoria[65] = 0x1F; // POP DS
    memoria[66] = 0xBA; // MOV DX,000E
    memoria[67] = 0x0E;
    memoria[68] = 0x00;
    memoria[69] = 0xB4; // MOV AH,09
    memoria[70] = 0x09;
    memoria[71] = 0xCD; // INT 21
    memoria[72] = 0x21;
    memoria[73] = 0xB8; // MOV AX,4C01
    memoria[74] = 0x01;
    memoria[75] = 0x4C;
    memoria[76] = 0xCD; // INT 21
    memoria[77] = 0x21;
    memoria[78] = 0x54;  // 'T'
    memoria[79] = 0x68;  // 'h'
    memoria[80] = 0x69;  // 'i'
    memoria[81] = 0x73;  // 's'
    memoria[82] = 0x20;  // ' '
    memoria[83] = 0x70;  // 'p'
    memoria[84] = 0x72;  // 'r'
    memoria[85] = 0x6F;  // 'o'
    memoria[86] = 0x67;  // 'g'
    memoria[87] = 0x72;  // 'r'
    memoria[88] = 0x61;  // 'a'
    memoria[89] = 0x6D;  // 'm'
    memoria[90] = 0x20;  // ' '
    memoria[91] = 0x69;  // 'i'
    memoria[92] = 0x73;  // 's'
    memoria[93] = 0x20;  // ' '
    memoria[94] = 0x61;  // 'a'
    memoria[95] = 0x20;  // ' '
    memoria[96] = 0x57;  // 'W'
    memoria[97] = 0x69;  // 'i'
    memoria[98] = 0x6E;  // 'n'
    memoria[99] = 0x33;  // '3'
    memoria[100] = 0x32; // '2'
    memoria[101] = 0x20; // ' '
    memoria[102] = 0x63; // 'c'
    memoria[103] = 0x6F; // 'o'
    memoria[104] = 0x6E; // 'n'
    memoria[105] = 0x73; // 's'
    memoria[106] = 0x6F; // 'o'
    memoria[107] = 0x6C; // 'l'
    memoria[108] = 0x65; // 'e'
    memoria[109] = 0x20; // ' '
    memoria[110] = 0x61; // 'a'
    memoria[111] = 0x70; // 'p'
    memoria[112] = 0x70; // 'p'
    memoria[113] = 0x6C; // 'l'
    memoria[114] = 0x69; // 'i'
    memoria[115] = 0x63; // 'c'
    memoria[116] = 0x61; // 'a'
    memoria[117] = 0x74; // 't'
    memoria[118] = 0x69; // 'i'
    memoria[119] = 0x6F; // 'o'
    memoria[120] = 0x6E; // 'n'
    memoria[121] = 0x2E; // '.'
    memoria[122] = 0x20; // ' '
    memoria[123] = 0x49; // 'I'
    memoria[124] = 0x74; // 't'
    memoria[125] = 0x20; // ' '
    memoria[126] = 0x63; // 'c'
    memoria[127] = 0x61; // 'a'
    memoria[128] = 0x6E; // 'n'
    memoria[129] = 0x6E; // 'n'
    memoria[130] = 0x6F; // 'o'
    memoria[131] = 0x74; // 't'
    memoria[132] = 0x20; // ' '
    memoria[133] = 0x62; // 'b'
    memoria[134] = 0x65; // 'e'
    memoria[135] = 0x20; // ' '
    memoria[136] = 0x72; // 'r'
    memoria[137] = 0x75; // 'u'
    memoria[138] = 0x6E; // 'n'
    memoria[139] = 0x20; // ' '
    memoria[140] = 0x75; // 'u'
    memoria[141] = 0x6E; // 'n'
    memoria[142] = 0x64; // 'd'
    memoria[143] = 0x65; // 'e'
    memoria[144] = 0x72; // 'r'
    memoria[145] = 0x20; // ' '
    memoria[146] = 0x4D; // 'M'
    memoria[147] = 0x53; // 'S'
    memoria[148] = 0x2D; // '-'
    memoria[149] = 0x44; // 'D'
    memoria[150] = 0x4F; // 'O'
    memoria[151] = 0x53; // 'S'
    memoria[152] = 0x2E; // '.'
    memoria[153] = 0x0D; // Carriage return
    memoria[154] = 0x0A; // Line feed
    memoria[155] = 0x24; // String end ('$')
    memoria[156] = 0x00;
    memoria[157] = 0x00;
    memoria[158] = 0x00;
    memoria[159] = 0x00;
    /* COFF HEADER - 8 Standard fields */
    memoria[160] = 0x50; // 'P'
    memoria[161] = 0x45; // 'E'
    memoria[162] = 0x00; // '\0'
    memoria[163] = 0x00; // '\0'
    memoria[164] = 0x4C; // Machine:
    memoria[165] = 0x01; // >= Intel 386
    memoria[166] = 0x01; // Number of
    memoria[167] = 0x00; // sections
    memoria[168] = 0x00; // Time/Date stamp
    memoria[169] = 0x00;
    memoria[170] = 0x53;
    memoria[171] = 0x4C;
    memoria[172] = 0x00; // Pointer to symbol
    memoria[173] = 0x00; // table
    memoria[174] = 0x00; // (deprecated)
    memoria[175] = 0x00;
    memoria[176] = 0x00; // Number of symbols
    memoria[177] = 0x00; // (deprecated)
    memoria[178] = 0x00;
    memoria[179] = 0x00;
    memoria[180] = 0xE0; // Size of optional
    memoria[181] = 0x00; // header
    memoria[182] = 0x02; // Characteristics:
    memoria[183] = 0x01; // 32BIT_MACHINE EXE
    /* OPTIONAL HEADER - 8 Standard fields */
    /* (For image files, it is required) */
    memoria[184] = 0x0B; // Magic number
    memoria[185] = 0x01; // (010B = PE32)
    memoria[186] = 0x01; // Maj.Linker Version
    memoria[187] = 0x00; // Min.Linker Version
    memoria[188] = 0x00; // Size of code
    memoria[189] = 0x06; // (text) section
    memoria[190] = 0x00;
    memoria[191] = 0x00;
    memoria[192] = 0x00; // Size of
    memoria[193] = 0x00; // initialized data
    memoria[194] = 0x00; // section
    memoria[195] = 0x00;
    memoria[196] = 0x00; // Size of
    memoria[197] = 0x00; // uninitialized
    memoria[198] = 0x00; // data section
    memoria[199] = 0x00;
    memoria[200] = 0x00; // Starting address
    memoria[201] = 0x15; // relative to the
    memoria[202] = 0x00; // image base
    memoria[203] = 0x00;
    memoria[204] = 0x00; // Base of code
    memoria[205] = 0x10;
    memoria[206] = 0x00;
    memoria[207] = 0x00;
    /* OPT.HEADER - 1 PE32 specific field */
    memoria[208] = 0x00; // Base of data
    memoria[209] = 0x20;
    memoria[210] = 0x00;
    memoria[211] = 0x00;
    /* OPT.HEADER - 21 Win-Specific Fields */
    memoria[212] = 0x00; // Image base
    memoria[213] = 0x00; // (Preferred
    memoria[214] = 0x40; // address of image
    memoria[215] = 0x00; // when loaded)
    memoria[216] = 0x00; // Section alignment
    memoria[217] = 0x10;
    memoria[218] = 0x00;
    memoria[219] = 0x00;
    memoria[220] = 0x00; // File alignment
    memoria[221] = 0x02; // (Default is 512)
    memoria[222] = 0x00;
    memoria[223] = 0x00;
    memoria[224] = 0x04; // Major OS version
    memoria[225] = 0x00;
    memoria[226] = 0x00; // Minor OS version
    memoria[227] = 0x00;
    memoria[228] = 0x00; // Maj. image version
    memoria[229] = 0x00;
    memoria[230] = 0x00; // Min. image version
    memoria[231] = 0x00;
    memoria[232] = 0x04; // Maj.subsystem ver.
    memoria[233] = 0x00;
    memoria[234] = 0x00; // Min.subsystem ver.
    memoria[235] = 0x00;
    memoria[236] = 0x00; // Win32 version
    memoria[237] = 0x00; // (Reserved, must
    memoria[238] = 0x00; // be zero)
    memoria[239] = 0x00;
    memoria[240] = 0x00; // Size of image
    memoria[241] = 0x20; // (It must be a
    memoria[242] = 0x00; // multiple of the
    memoria[243] = 0x00; // section alignment)
    memoria[244] = 0x00; // Size of headers
    memoria[245] = 0x02; // (rounded up to a
    memoria[246] = 0x00; // multiple of the
    memoria[247] = 0x00; // file alignment)
    memoria[248] = 0x00; // Checksum
    memoria[249] = 0x00;
    memoria[250] = 0x00;
    memoria[251] = 0x00;
    memoria[252] = 0x03; // Windows subsystem
    memoria[253] = 0x00; // (03 = console)
    memoria[254] = 0x00; // DLL characmemoria[255] = 0x00; // teristics
    memoria[256] = 0x00; // Size of stack
    memoria[257] = 0x00; // reserve
    memoria[258] = 0x10;
    memoria[259] = 0x00;
    memoria[260] = 0x00; // Size of stack
    memoria[261] = 0x10; // commit
    memoria[262] = 0x00;
    memoria[263] = 0x00;
    memoria[264] = 0x00; // Size of heap
    memoria[265] = 0x00; // reserve
    memoria[266] = 0x10;
    memoria[267] = 0x00;
    memoria[268] = 0x00; // Size of heap
    memoria[269] = 0x10; // commit
    memoria[270] = 0x00;
    memoria[271] = 0x00;
    memoria[272] = 0x00; // Loader flags
    memoria[273] = 0x00; // (Reserved, must
    memoria[274] = 0x00; // be zero)
    memoria[275] = 0x00;
    memoria[276] = 0x10; // Number of
    memoria[277] = 0x00; // relative virtual
    memoria[278] = 0x00; // addresses (RVAs)
    memoria[279] = 0x00;
    /* OPT. HEADER - 16 Data Directories */
    memoria[280] = 0x00; // Export Table
    memoria[281] = 0x00;
    memoria[282] = 0x00;
    memoria[283] = 0x00;
    memoria[284] = 0x00;
    memoria[285] = 0x00;
    memoria[286] = 0x00;
    memoria[287] = 0x00;
    memoria[288] = 0x1C; // Import Table
    memoria[289] = 0x10;
    memoria[290] = 0x00;
    memoria[291] = 0x00;
    memoria[292] = 0x28;
    memoria[293] = 0x00;
    memoria[294] = 0x00;
    memoria[295] = 0x00;
    memoria[296] = 0x00; // Resource Table
    memoria[297] = 0x00;
    memoria[298] = 0x00;
    memoria[299] = 0x00;
    memoria[300] = 0x00;
    memoria[301] = 0x00;
    memoria[302] = 0x00;
    memoria[303] = 0x00;
    memoria[304] = 0x00; // Exception Table
    memoria[305] = 0x00;
    memoria[306] = 0x00;
    memoria[307] = 0x00;
    memoria[308] = 0x00;
    memoria[309] = 0x00;
    memoria[310] = 0x00;
    memoria[311] = 0x00;
    memoria[312] = 0x00; // Certificate Table
    memoria[313] = 0x00;
    memoria[314] = 0x00;
    memoria[315] = 0x00;
    memoria[316] = 0x00;
    memoria[317] = 0x00;
    memoria[318] = 0x00;
    memoria[319] = 0x00;
    memoria[320] = 0x00; // Base Relocation
    memoria[321] = 0x00; // Table
    memoria[322] = 0x00;
    memoria[323] = 0x00;
    memoria[324] = 0x00;
    memoria[325] = 0x00;
    memoria[326] = 0x00;
    memoria[327] = 0x00;
    memoria[328] = 0x00; // Debug
    memoria[329] = 0x00;
    memoria[330] = 0x00;
    memoria[331] = 0x00;
    memoria[332] = 0x00;
    memoria[333] = 0x00;
    memoria[334] = 0x00;
    memoria[335] = 0x00;
    memoria[336] = 0x00; // Architecture
    memoria[337] = 0x00;
    memoria[338] = 0x00;
    memoria[339] = 0x00;
    memoria[340] = 0x00;
    memoria[341] = 0x00;
    memoria[342] = 0x00;
    memoria[343] = 0x00;
    memoria[344] = 0x00; // Global Ptr
    memoria[345] = 0x00;
    memoria[346] = 0x00;
    memoria[347] = 0x00;
    memoria[348] = 0x00;
    memoria[349] = 0x00;
    memoria[350] = 0x00;
    memoria[351] = 0x00;
    memoria[352] = 0x00; // TLS Table
    memoria[353] = 0x00;
    memoria[354] = 0x00;
    memoria[355] = 0x00;
    memoria[356] = 0x00;
    memoria[357] = 0x00;
    memoria[358] = 0x00;
    memoria[359] = 0x00;
    memoria[360] = 0x00; // Load Config Table
    memoria[361] = 0x00;
    memoria[362] = 0x00;
    memoria[363] = 0x00;
    memoria[364] = 0x00;
    memoria[365] = 0x00;
    memoria[366] = 0x00;
    memoria[367] = 0x00;
    memoria[368] = 0x00; // Bound Import
    memoria[369] = 0x00;
    memoria[370] = 0x00;
    memoria[371] = 0x00;
    memoria[372] = 0x00;
    memoria[373] = 0x00;
    memoria[374] = 0x00;
    memoria[375] = 0x00;
    memoria[376] = 0x00; // IAT
    memoria[377] = 0x10;
    memoria[378] = 0x00;
    memoria[379] = 0x00;
    memoria[380] = 0x1C;
    memoria[381] = 0x00;
    memoria[382] = 0x00;
    memoria[383] = 0x00;
    memoria[384] = 0x00; // Delay Import
    memoria[385] = 0x00; // Descriptor
    memoria[386] = 0x00;
    memoria[387] = 0x00;
    memoria[388] = 0x00;
    memoria[389] = 0x00;
    memoria[390] = 0x00;
    memoria[391] = 0x00;
    memoria[392] = 0x00; // CLR Runtime
    memoria[393] = 0x00; // Header
    memoria[394] = 0x00;
    memoria[395] = 0x00;
    memoria[396] = 0x00;
    memoria[397] = 0x00;
    memoria[398] = 0x00;
    memoria[399] = 0x00;
    memoria[400] = 0x00; // Reserved, must be
    memoria[401] = 0x00; // zero
    memoria[402] = 0x00;
    memoria[403] = 0x00;
    memoria[404] = 0x00;
    memoria[405] = 0x00;
    memoria[406] = 0x00;
    memoria[407] = 0x00;
    /* SECTIONS TABLE (40 bytes per entry) */
    /* FIRST ENTRY: TEXT HEADER */
    memoria[408] = 0x2E; // '.' (Name)
    memoria[409] = 0x74; // 't'
    memoria[410] = 0x65; // 'e'
    memoria[411] = 0x78; // 'x'
    memoria[412] = 0x74; // 't'
    memoria[413] = 0x00;
    memoria[414] = 0x00;
    memoria[415] = 0x00;
    memoria[416] = 0x24; // Virtual size
    memoria[417] = 0x05;
    memoria[418] = 0x00;
    memoria[419] = 0x00;
    memoria[420] = 0x00; // Virtual address
    memoria[421] = 0x10;
    memoria[422] = 0x00;
    memoria[423] = 0x00;
    memoria[424] = 0x00; // Size of raw data
    memoria[425] = 0x06;
    memoria[426] = 0x00;
    memoria[427] = 0x00;
    memoria[428] = 0x00; // Pointer to
    memoria[429] = 0x02; // raw data
    memoria[430] = 0x00;
    memoria[431] = 0x00;
    memoria[432] = 0x00; // Pointer to
    memoria[433] = 0x00; // relocations
    memoria[434] = 0x00;
    memoria[435] = 0x00;
    memoria[436] = 0x00; // Pointer to
    memoria[437] = 0x00; // line numbers
    memoria[438] = 0x00;
    memoria[439] = 0x00;
    memoria[440] = 0x00; // Number of
    memoria[441] = 0x00; // relocations
    memoria[442] = 0x00; // Number of
    memoria[443] = 0x00; // line numbers
    memoria[444] = 0x20; // Characteristics
    memoria[445] = 0x00; // (Readable,
    memoria[446] = 0x00; // Writeable &
    memoria[447] = 0xE0; // Executable)
    memoria[448] = 0x00;
    memoria[449] = 0x00;
    memoria[450] = 0x00;
    memoria[451] = 0x00;
    memoria[452] = 0x00;
    memoria[453] = 0x00;
    memoria[454] = 0x00;
    memoria[455] = 0x00;
    memoria[456] = 0x00;
    memoria[457] = 0x00;
    memoria[458] = 0x00;
    memoria[459] = 0x00;
    memoria[460] = 0x00;
    memoria[461] = 0x00;
    memoria[462] = 0x00;
    memoria[463] = 0x00;
    memoria[464] = 0x00;
    memoria[465] = 0x00;
    memoria[466] = 0x00;
    memoria[467] = 0x00;
    memoria[468] = 0x00;
    memoria[469] = 0x00;
    memoria[470] = 0x00;
    memoria[471] = 0x00;
    memoria[472] = 0x00;
    memoria[473] = 0x00;
    memoria[474] = 0x00;
    memoria[475] = 0x00;
    memoria[476] = 0x00;
    memoria[477] = 0x00;
    memoria[478] = 0x00;
    memoria[479] = 0x00;
    memoria[480] = 0x00;
    memoria[481] = 0x00;
    memoria[482] = 0x00;
    memoria[483] = 0x00;
    memoria[484] = 0x00;
    memoria[485] = 0x00;
    memoria[486] = 0x00;
    memoria[487] = 0x00;
    memoria[488] = 0x00;
    memoria[489] = 0x00;
    memoria[490] = 0x00;
    memoria[491] = 0x00;
    memoria[492] = 0x00;
    memoria[493] = 0x00;
    memoria[494] = 0x00;
    memoria[495] = 0x00;
    memoria[496] = 0x00;
    memoria[497] = 0x00;
    memoria[498] = 0x00;
    memoria[499] = 0x00;
    memoria[500] = 0x00;
    memoria[501] = 0x00;
    memoria[502] = 0x00;
    memoria[503] = 0x00;
    memoria[504] = 0x00;
    memoria[505] = 0x00;
    memoria[506] = 0x00;
    memoria[507] = 0x00;
    memoria[508] = 0x00;
    memoria[509] = 0x00;
    memoria[510] = 0x00;
    memoria[511] = 0x00;
    memoria[512] = 0x6E; // Inicio de la seccion .text
    memoria[513] = 0x10;
    memoria[514] = 0x00;
    memoria[515] = 0x00;
    memoria[516] = 0x7C;
    memoria[517] = 0x10;
    memoria[518] = 0x00;
    memoria[519] = 0x00;
    memoria[520] = 0x8C;
    memoria[521] = 0x10;
    memoria[522] = 0x00;
    memoria[523] = 0x00;
    memoria[524] = 0x98;
    memoria[525] = 0x10;
    memoria[526] = 0x00;
    memoria[527] = 0x00;
    memoria[528] = 0xA4;
    memoria[529] = 0x10;
    memoria[530] = 0x00;
    memoria[531] = 0x00;
    memoria[532] = 0xB6;
    memoria[533] = 0x10;
    memoria[534] = 0x00;
    memoria[535] = 0x00;
    memoria[536] = 0x00;
    memoria[537] = 0x00;
    memoria[538] = 0x00;
    memoria[539] = 0x00;
    memoria[540] = 0x52;
    memoria[541] = 0x10;
    memoria[542] = 0x00;
    memoria[543] = 0x00;
    memoria[544] = 0x00;
    memoria[545] = 0x00;
    memoria[546] = 0x00;
    memoria[547] = 0x00;
    memoria[548] = 0x00;
    memoria[549] = 0x00;
    memoria[550] = 0x00;
    memoria[551] = 0x00;
    memoria[552] = 0x44;
    memoria[553] = 0x10;
    memoria[554] = 0x00;
    memoria[555] = 0x00;
    memoria[556] = 0x00;
    memoria[557] = 0x10;
    memoria[558] = 0x00;
    memoria[559] = 0x00;
    memoria[560] = 0x00;
    memoria[561] = 0x00;
    memoria[562] = 0x00;
    memoria[563] = 0x00;
    memoria[564] = 0x00;
    memoria[565] = 0x00;
    memoria[566] = 0x00;
    memoria[567] = 0x00;
    memoria[568] = 0x00;
    memoria[569] = 0x00;
    memoria[570] = 0x00;
    memoria[571] = 0x00;
    memoria[572] = 0x00;
    memoria[573] = 0x00;
    memoria[574] = 0x00;
    memoria[575] = 0x00;
    memoria[576] = 0x00;
    memoria[577] = 0x00;
    memoria[578] = 0x00;
    memoria[579] = 0x00;
    memoria[580] = 0x4B;
    memoria[581] = 0x45;
    memoria[582] = 0x52;
    memoria[583] = 0x4E;
    memoria[584] = 0x45;
    memoria[585] = 0x4C;
    memoria[586] = 0x33;
    memoria[587] = 0x32;
    memoria[588] = 0x2E;
    memoria[589] = 0x64;
    memoria[590] = 0x6C;
    memoria[591] = 0x6C;
    memoria[592] = 0x00;
    memoria[593] = 0x00;
    memoria[594] = 0x6E;
    memoria[595] = 0x10;
    memoria[596] = 0x00;
    memoria[597] = 0x00;
    memoria[598] = 0x7C;
    memoria[599] = 0x10;
    memoria[600] = 0x00;
    memoria[601] = 0x00;
    memoria[602] = 0x8C;
    memoria[603] = 0x10;
    memoria[604] = 0x00;
    memoria[605] = 0x00;
    memoria[606] = 0x98;
    memoria[607] = 0x10;
    memoria[608] = 0x00;
    memoria[609] = 0x00;
    memoria[610] = 0xA4;
    memoria[611] = 0x10;
    memoria[612] = 0x00;
    memoria[613] = 0x00;
    memoria[614] = 0xB6;
    memoria[615] = 0x10;
    memoria[616] = 0x00;
    memoria[617] = 0x00;
    memoria[618] = 0x00;
    memoria[619] = 0x00;
    memoria[620] = 0x00;
    memoria[621] = 0x00;
    memoria[622] = 0x00;
    memoria[623] = 0x00;
    memoria[624] = 0x45;
    memoria[625] = 0x78;
    memoria[626] = 0x69;
    memoria[627] = 0x74;
    memoria[628] = 0x50;
    memoria[629] = 0x72;
    memoria[630] = 0x6F;
    memoria[631] = 0x63;
    memoria[632] = 0x65;
    memoria[633] = 0x73;
    memoria[634] = 0x73;
    memoria[635] = 0x00;
    memoria[636] = 0x00;
    memoria[637] = 0x00;
    memoria[638] = 0x47;
    memoria[639] = 0x65;
    memoria[640] = 0x74;
    memoria[641] = 0x53;
    memoria[642] = 0x74;
    memoria[643] = 0x64;
    memoria[644] = 0x48;
    memoria[645] = 0x61;
    memoria[646] = 0x6E;
    memoria[647] = 0x64;
    memoria[648] = 0x6C;
    memoria[649] = 0x65;
    memoria[650] = 0x00;
    memoria[651] = 0x00;
    memoria[652] = 0x00;
    memoria[653] = 0x00;
    memoria[654] = 0x52;
    memoria[655] = 0x65;
    memoria[656] = 0x61;
    memoria[657] = 0x64;
    memoria[658] = 0x46;
    memoria[659] = 0x69;
    memoria[660] = 0x6C;
    memoria[661] = 0x65;
    memoria[662] = 0x00;
    memoria[663] = 0x00;
    memoria[664] = 0x00;
    memoria[665] = 0x00;
    memoria[666] = 0x57;
    memoria[667] = 0x72;
    memoria[668] = 0x69;
    memoria[669] = 0x74;
    memoria[670] = 0x65;
    memoria[671] = 0x46;
    memoria[672] = 0x69;
    memoria[673] = 0x6C;
    memoria[674] = 0x65;
    memoria[675] = 0x00;
    memoria[676] = 0x00;
    memoria[677] = 0x00;
    memoria[678] = 0x47;
    memoria[679] = 0x65;
    memoria[680] = 0x74;
    memoria[681] = 0x43;
    memoria[682] = 0x6F;
    memoria[683] = 0x6E;
    memoria[684] = 0x73;
    memoria[685] = 0x6F;
    memoria[686] = 0x6C;
    memoria[687] = 0x65;
    memoria[688] = 0x4D;
    memoria[689] = 0x6F;
    memoria[690] = 0x64;
    memoria[691] = 0x65;
    memoria[692] = 0x00;
    memoria[693] = 0x00;
    memoria[694] = 0x00;
    memoria[695] = 0x00;
    memoria[696] = 0x53;
    memoria[697] = 0x65;
    memoria[698] = 0x74;
    memoria[699] = 0x43;
    memoria[700] = 0x6F;
    memoria[701] = 0x6E;
    memoria[702] = 0x73;
    memoria[703] = 0x6F;
    memoria[704] = 0x6C;
    memoria[705] = 0x65;
    memoria[706] = 0x4D;
    memoria[707] = 0x6F;
    memoria[708] = 0x64;
    memoria[709] = 0x65;
    memoria[710] = 0x00;
    memoria[711] = 0x00;
    memoria[712] = 0x00;
    memoria[713] = 0x00;
    memoria[714] = 0x00;
    memoria[715] = 0x00;
    memoria[716] = 0x00;
    memoria[717] = 0x00;
    memoria[718] = 0x00;
    memoria[719] = 0x00;
    memoria[720] = 0x50;
    memoria[721] = 0xA2;
    memoria[722] = 0x1C;
    memoria[723] = 0x11;
    memoria[724] = 0x40;
    memoria[725] = 0x00;
    memoria[726] = 0x31;
    memoria[727] = 0xC0;
    memoria[728] = 0x03;
    memoria[729] = 0x05;
    memoria[730] = 0x2C;
    memoria[731] = 0x11;
    memoria[732] = 0x40;
    memoria[733] = 0x00;
    memoria[734] = 0x75;
    memoria[735] = 0x0D;
    memoria[736] = 0x6A;
    memoria[737] = 0xF5;
    memoria[738] = 0xFF;
    memoria[739] = 0x15;
    memoria[740] = 0x04;
    memoria[741] = 0x10;
    memoria[742] = 0x40;
    memoria[743] = 0x00;
    memoria[744] = 0xA3;
    memoria[745] = 0x2C;
    memoria[746] = 0x11;
    memoria[747] = 0x40;
    memoria[748] = 0x00;
    memoria[749] = 0x6A;
    memoria[750] = 0x00;
    memoria[751] = 0x68;
    memoria[752] = 0x30;
    memoria[753] = 0x11;
    memoria[754] = 0x40;
    memoria[755] = 0x00;
    memoria[756] = 0x6A;
    memoria[757] = 0x01;
    memoria[758] = 0x68;
    memoria[759] = 0x1C;
    memoria[760] = 0x11;
    memoria[761] = 0x40;
    memoria[762] = 0x00;
    memoria[763] = 0x50;
    memoria[764] = 0xFF;
    memoria[765] = 0x15;
    memoria[766] = 0x0C;
    memoria[767] = 0x10;
    memoria[768] = 0x40;
    memoria[769] = 0x00;
    memoria[770] = 0x09;
    memoria[771] = 0xC0;
    memoria[772] = 0x75;
    memoria[773] = 0x08;
    memoria[774] = 0x6A;
    memoria[775] = 0x00;
    memoria[776] = 0xFF;
    memoria[777] = 0x15;
    memoria[778] = 0x00;
    memoria[779] = 0x10;
    memoria[780] = 0x40;
    memoria[781] = 0x00;
    memoria[782] = 0x81;
    memoria[783] = 0x3D;
    memoria[784] = 0x30;
    memoria[785] = 0x11;
    memoria[786] = 0x40;
    memoria[787] = 0x00;
    memoria[788] = 0x01;
    memoria[789] = 0x00;
    memoria[790] = 0x00;
    memoria[791] = 0x00;
    memoria[792] = 0x75;
    memoria[793] = 0xEC;
    memoria[794] = 0x58;
    memoria[795] = 0xC3;
    memoria[796] = 0x00;
    memoria[797] = 0x57;
    memoria[798] = 0x72;
    memoria[799] = 0x69;
    memoria[800] = 0x74;
    memoria[801] = 0x65;
    memoria[802] = 0x20;
    memoria[803] = 0x65;
    memoria[804] = 0x72;
    memoria[805] = 0x72;
    memoria[806] = 0x6F;
    memoria[807] = 0x72;
    memoria[808] = 0x00;
    memoria[809] = 0x00;
    memoria[810] = 0x00;
    memoria[811] = 0x00;
    memoria[812] = 0x00;
    memoria[813] = 0x00;
    memoria[814] = 0x00;
    memoria[815] = 0x00;
    memoria[816] = 0x00;
    memoria[817] = 0x00;
    memoria[818] = 0x00;
    memoria[819] = 0x00;
    memoria[820] = 0x00;
    memoria[821] = 0x00;
    memoria[822] = 0x00;
    memoria[823] = 0x00;
    memoria[824] = 0x00;
    memoria[825] = 0x00;
    memoria[826] = 0x00;
    memoria[827] = 0x00;
    memoria[828] = 0x00;
    memoria[829] = 0x00;
    memoria[830] = 0x00;
    memoria[831] = 0x00;
    memoria[832] = 0x60;
    memoria[833] = 0x31;
    memoria[834] = 0xC0;
    memoria[835] = 0x03;
    memoria[836] = 0x05;
    memoria[837] = 0xCC;
    memoria[838] = 0x11;
    memoria[839] = 0x40;
    memoria[840] = 0x00;
    memoria[841] = 0x75;
    memoria[842] = 0x37;
    memoria[843] = 0x6A;
    memoria[844] = 0xF6;
    memoria[845] = 0xFF;
    memoria[846] = 0x15;
    memoria[847] = 0x04;
    memoria[848] = 0x10;
    memoria[849] = 0x40;
    memoria[850] = 0x00;
    memoria[851] = 0xA3;
    memoria[852] = 0xCC;
    memoria[853] = 0x11;
    memoria[854] = 0x40;
    memoria[855] = 0x00;
    memoria[856] = 0x68;
    memoria[857] = 0xD0;
    memoria[858] = 0x11;
    memoria[859] = 0x40;
    memoria[860] = 0x00;
    memoria[861] = 0x50;
    memoria[862] = 0xFF;
    memoria[863] = 0x15;
    memoria[864] = 0x10;
    memoria[865] = 0x10;
    memoria[866] = 0x40;
    memoria[867] = 0x00;
    memoria[868] = 0x80;
    memoria[869] = 0x25;
    memoria[870] = 0xD0;
    memoria[871] = 0x11;
    memoria[872] = 0x40;
    memoria[873] = 0x00;
    memoria[874] = 0xF9;
    memoria[875] = 0xFF;
    memoria[876] = 0x35;
    memoria[877] = 0xD0;
    memoria[878] = 0x11;
    memoria[879] = 0x40;
    memoria[880] = 0x00;
    memoria[881] = 0xFF;
    memoria[882] = 0x35;
    memoria[883] = 0xCC;
    memoria[884] = 0x11;
    memoria[885] = 0x40;
    memoria[886] = 0x00;
    memoria[887] = 0xFF;
    memoria[888] = 0x15;
    memoria[889] = 0x14;
    memoria[890] = 0x10;
    memoria[891] = 0x40;
    memoria[892] = 0x00;
    memoria[893] = 0xA1;
    memoria[894] = 0xCC;
    memoria[895] = 0x11;
    memoria[896] = 0x40;
    memoria[897] = 0x00;
    memoria[898] = 0x6A;
    memoria[899] = 0x00;
    memoria[900] = 0x68;
    memoria[901] = 0xD4;
    memoria[902] = 0x11;
    memoria[903] = 0x40;
    memoria[904] = 0x00;
    memoria[905] = 0x6A;
    memoria[906] = 0x01;
    memoria[907] = 0x68;
    memoria[908] = 0xBE;
    memoria[909] = 0x11;
    memoria[910] = 0x40;
    memoria[911] = 0x00;
    memoria[912] = 0x50;
    memoria[913] = 0xFF;
    memoria[914] = 0x15;
    memoria[915] = 0x08;
    memoria[916] = 0x10;
    memoria[917] = 0x40;
    memoria[918] = 0x00;
    memoria[919] = 0x09;
    memoria[920] = 0xC0;
    memoria[921] = 0x61;
    memoria[922] = 0x90;
    memoria[923] = 0x75;
    memoria[924] = 0x08;
    memoria[925] = 0x6A;
    memoria[926] = 0x00;
    memoria[927] = 0xFF;
    memoria[928] = 0x15;
    memoria[929] = 0x00;
    memoria[930] = 0x10;
    memoria[931] = 0x40;
    memoria[932] = 0x00;
    memoria[933] = 0x0F;
    memoria[934] = 0xB6;
    memoria[935] = 0x05;
    memoria[936] = 0xBE;
    memoria[937] = 0x11;
    memoria[938] = 0x40;
    memoria[939] = 0x00;
    memoria[940] = 0x81;
    memoria[941] = 0x3D;
    memoria[942] = 0xD4;
    memoria[943] = 0x11;
    memoria[944] = 0x40;
    memoria[945] = 0x00;
    memoria[946] = 0x01;
    memoria[947] = 0x00;
    memoria[948] = 0x00;
    memoria[949] = 0x00;
    memoria[950] = 0x74;
    memoria[951] = 0x05;
    memoria[952] = 0xB8;
    memoria[953] = 0xFF;
    memoria[954] = 0xFF;
    memoria[955] = 0xFF;
    memoria[956] = 0xFF;
    memoria[957] = 0xC3;
    memoria[958] = 0x00;
    memoria[959] = 0x52;
    memoria[960] = 0x65;
    memoria[961] = 0x61;
    memoria[962] = 0x64;
    memoria[963] = 0x20;
    memoria[964] = 0x65;
    memoria[965] = 0x72;
    memoria[966] = 0x72;
    memoria[967] = 0x6F;
    memoria[968] = 0x72;
    memoria[969] = 0x00;
    memoria[970] = 0x00;
    memoria[971] = 0x00;
    memoria[972] = 0x00;
    memoria[973] = 0x00;
    memoria[974] = 0x00;
    memoria[975] = 0x00;
    memoria[976] = 0x00;
    memoria[977] = 0x00;
    memoria[978] = 0x00;
    memoria[979] = 0x00;
    memoria[980] = 0x00;
    memoria[981] = 0x00;
    memoria[982] = 0x00;
    memoria[983] = 0x00;
    memoria[984] = 0x00;
    memoria[985] = 0x00;
    memoria[986] = 0x00;
    memoria[987] = 0x00;
    memoria[988] = 0x00;
    memoria[989] = 0x00;
    memoria[990] = 0x00;
    memoria[991] = 0x00;
    memoria[992] = 0x60;
    memoria[993] = 0x89;
    memoria[994] = 0xC6;
    memoria[995] = 0x30;
    memoria[996] = 0xC0;
    memoria[997] = 0x02;
    memoria[998] = 0x06;
    memoria[999] = 0x74;
    memoria[1000] = 0x08;
    memoria[1001] = 0x46;
    memoria[1002] = 0xE8;
    memoria[1003] = 0xE1;
    memoria[1004] = 0xFE;
    memoria[1005] = 0xFF;
    memoria[1006] = 0xFF;
    memoria[1007] = 0xEB;
    memoria[1008] = 0xF2;
    memoria[1009] = 0x61;
    memoria[1010] = 0x90;
    memoria[1011] = 0xC3;
    memoria[1012] = 0x00;
    memoria[1013] = 0x00;
    memoria[1014] = 0x00;
    memoria[1015] = 0x00;
    memoria[1016] = 0x00;
    memoria[1017] = 0x00;
    memoria[1018] = 0x00;
    memoria[1019] = 0x00;
    memoria[1020] = 0x00;
    memoria[1021] = 0x00;
    memoria[1022] = 0x00;
    memoria[1023] = 0x00;
    memoria[1024] = 0x04;
    memoria[1025] = 0x30;
    memoria[1026] = 0xE8;
    memoria[1027] = 0xC9;
    memoria[1028] = 0xFE;
    memoria[1029] = 0xFF;
    memoria[1030] = 0xFF;
    memoria[1031] = 0xC3;
    memoria[1032] = 0x00;
    memoria[1033] = 0x00;
    memoria[1034] = 0x00;
    memoria[1035] = 0x00;
    memoria[1036] = 0x00;
    memoria[1037] = 0x00;
    memoria[1038] = 0x00;
    memoria[1039] = 0x00;
    memoria[1040] = 0xB0;
    memoria[1041] = 0x0D;
    memoria[1042] = 0xE8;
    memoria[1043] = 0xB9;
    memoria[1044] = 0xFE;
    memoria[1045] = 0xFF;
    memoria[1046] = 0xFF;
    memoria[1047] = 0xB0;
    memoria[1048] = 0x0A;
    memoria[1049] = 0xE8;
    memoria[1050] = 0xB2;
    memoria[1051] = 0xFE;
    memoria[1052] = 0xFF;
    memoria[1053] = 0xFF;
    memoria[1054] = 0xC3;
    memoria[1055] = 0x00;
    memoria[1056] = 0x3D;
    memoria[1057] = 0x00;
    memoria[1058] = 0x00;
    memoria[1059] = 0x00;
    memoria[1060] = 0x80;
    memoria[1061] = 0x75;
    memoria[1062] = 0x4E;
    memoria[1063] = 0xB0;
    memoria[1064] = 0x2D;
    memoria[1065] = 0xE8;
    memoria[1066] = 0xA2;
    memoria[1067] = 0xFE;
    memoria[1068] = 0xFF;
    memoria[1069] = 0xFF;
    memoria[1070] = 0xB0;
    memoria[1071] = 0x02;
    memoria[1072] = 0xE8;
    memoria[1073] = 0xCB;
    memoria[1074] = 0xFF;
    memoria[1075] = 0xFF;
    memoria[1076] = 0xFF;
    memoria[1077] = 0xB0;
    memoria[1078] = 0x01;
    memoria[1079] = 0xE8;
    memoria[1080] = 0xC4;
    memoria[1081] = 0xFF;
    memoria[1082] = 0xFF;
    memoria[1083] = 0xFF;
    memoria[1084] = 0xB0;
    memoria[1085] = 0x04;
    memoria[1086] = 0xE8;
    memoria[1087] = 0xBD;
    memoria[1088] = 0xFF;
    memoria[1089] = 0xFF;
    memoria[1090] = 0xFF;
    memoria[1091] = 0xB0;
    memoria[1092] = 0x07;
    memoria[1093] = 0xE8;
    memoria[1094] = 0xB6;
    memoria[1095] = 0xFF;
    memoria[1096] = 0xFF;
    memoria[1097] = 0xFF;
    memoria[1098] = 0xB0;
    memoria[1099] = 0x04;
    memoria[1100] = 0xE8;
    memoria[1101] = 0xAF;
    memoria[1102] = 0xFF;
    memoria[1103] = 0xFF;
    memoria[1104] = 0xFF;
    memoria[1105] = 0xB0;
    memoria[1106] = 0x08;
    memoria[1107] = 0xE8;
    memoria[1108] = 0xA8;
    memoria[1109] = 0xFF;
    memoria[1110] = 0xFF;
    memoria[1111] = 0xFF;
    memoria[1112] = 0xB0;
    memoria[1113] = 0x03;
    memoria[1114] = 0xE8;
    memoria[1115] = 0xA1;
    memoria[1116] = 0xFF;
    memoria[1117] = 0xFF;
    memoria[1118] = 0xFF;
    memoria[1119] = 0xB0;
    memoria[1120] = 0x06;
    memoria[1121] = 0xE8;
    memoria[1122] = 0x9A;
    memoria[1123] = 0xFF;
    memoria[1124] = 0xFF;
    memoria[1125] = 0xFF;
    memoria[1126] = 0xB0;
    memoria[1127] = 0x04;
    memoria[1128] = 0xE8;
    memoria[1129] = 0x93;
    memoria[1130] = 0xFF;
    memoria[1131] = 0xFF;
    memoria[1132] = 0xFF;
    memoria[1133] = 0xB0;
    memoria[1134] = 0x08;
    memoria[1135] = 0xE8;
    memoria[1136] = 0x8C;
    memoria[1137] = 0xFF;
    memoria[1138] = 0xFF;
    memoria[1139] = 0xFF;
    memoria[1140] = 0xC3;
    memoria[1141] = 0x3D;
    memoria[1142] = 0x00;
    memoria[1143] = 0x00;
    memoria[1144] = 0x00;
    memoria[1145] = 0x00;
    memoria[1146] = 0x7D;
    memoria[1147] = 0x0B;
    memoria[1148] = 0x50;
    memoria[1149] = 0xB0;
    memoria[1150] = 0x2D;
    memoria[1151] = 0xE8;
    memoria[1152] = 0x4C;
    memoria[1153] = 0xFE;
    memoria[1154] = 0xFF;
    memoria[1155] = 0xFF;
    memoria[1156] = 0x58;
    memoria[1157] = 0xF7;
    memoria[1158] = 0xD8;
    memoria[1159] = 0x3D;
    memoria[1160] = 0x0A;
    memoria[1161] = 0x00;
    memoria[1162] = 0x00;
    memoria[1163] = 0x00;
    memoria[1164] = 0x0F;
    memoria[1165] = 0x8C;
    memoria[1166] = 0xEF;
    memoria[1167] = 0x00;
    memoria[1168] = 0x00;
    memoria[1169] = 0x00;
    memoria[1170] = 0x3D;
    memoria[1171] = 0x64;
    memoria[1172] = 0x00;
    memoria[1173] = 0x00;
    memoria[1174] = 0x00;
    memoria[1175] = 0x0F;
    memoria[1176] = 0x8C;
    memoria[1177] = 0xD1;
    memoria[1178] = 0x00;
    memoria[1179] = 0x00;
    memoria[1180] = 0x00;
    memoria[1181] = 0x3D;
    memoria[1182] = 0xE8;
    memoria[1183] = 0x03;
    memoria[1184] = 0x00;
    memoria[1185] = 0x00;
    memoria[1186] = 0x0F;
    memoria[1187] = 0x8C;
    memoria[1188] = 0xB3;
    memoria[1189] = 0x00;
    memoria[1190] = 0x00;
    memoria[1191] = 0x00;
    memoria[1192] = 0x3D;
    memoria[1193] = 0x10;
    memoria[1194] = 0x27;
    memoria[1195] = 0x00;
    memoria[1196] = 0x00;
    memoria[1197] = 0x0F;
    memoria[1198] = 0x8C;
    memoria[1199] = 0x95;
    memoria[1200] = 0x00;
    memoria[1201] = 0x00;
    memoria[1202] = 0x00;
    memoria[1203] = 0x3D;
    memoria[1204] = 0xA0;
    memoria[1205] = 0x86;
    memoria[1206] = 0x01;
    memoria[1207] = 0x00;
    memoria[1208] = 0x7C;
    memoria[1209] = 0x7B;
    memoria[1210] = 0x3D;
    memoria[1211] = 0x40;
    memoria[1212] = 0x42;
    memoria[1213] = 0x0F;
    memoria[1214] = 0x00;
    memoria[1215] = 0x7C;
    memoria[1216] = 0x61;
    memoria[1217] = 0x3D;
    memoria[1218] = 0x80;
    memoria[1219] = 0x96;
    memoria[1220] = 0x98;
    memoria[1221] = 0x00;
    memoria[1222] = 0x7C;
    memoria[1223] = 0x47;
    memoria[1224] = 0x3D;
    memoria[1225] = 0x00;
    memoria[1226] = 0xE1;
    memoria[1227] = 0xF5;
    memoria[1228] = 0x05;
    memoria[1229] = 0x7C;
    memoria[1230] = 0x2D;
    memoria[1231] = 0x3D;
    memoria[1232] = 0x00;
    memoria[1233] = 0xCA;
    memoria[1234] = 0x9A;
    memoria[1235] = 0x3B;
    memoria[1236] = 0x7C;
    memoria[1237] = 0x13;
    memoria[1238] = 0xBA;
    memoria[1239] = 0x00;
    memoria[1240] = 0x00;
    memoria[1241] = 0x00;
    memoria[1242] = 0x00;
    memoria[1243] = 0xBB;
    memoria[1244] = 0x00;
    memoria[1245] = 0xCA;
    memoria[1246] = 0x9A;
    memoria[1247] = 0x3B;
    memoria[1248] = 0xF7;
    memoria[1249] = 0xFB;
    memoria[1250] = 0x52;
    memoria[1251] = 0xE8;
    memoria[1252] = 0x18;
    memoria[1253] = 0xFF;
    memoria[1254] = 0xFF;
    memoria[1255] = 0xFF;
    memoria[1256] = 0x58;
    memoria[1257] = 0xBA;
    memoria[1258] = 0x00;
    memoria[1259] = 0x00;
    memoria[1260] = 0x00;
    memoria[1261] = 0x00;
    memoria[1262] = 0xBB;
    memoria[1263] = 0x00;
    memoria[1264] = 0xE1;
    memoria[1265] = 0xF5;
    memoria[1266] = 0x05;
    memoria[1267] = 0xF7;
    memoria[1268] = 0xFB;
    memoria[1269] = 0x52;
    memoria[1270] = 0xE8;
    memoria[1271] = 0x05;
    memoria[1272] = 0xFF;
    memoria[1273] = 0xFF;
    memoria[1274] = 0xFF;
    memoria[1275] = 0x58;
    memoria[1276] = 0xBA;
    memoria[1277] = 0x00;
    memoria[1278] = 0x00;
    memoria[1279] = 0x00;
    memoria[1280] = 0x00;
    memoria[1281] = 0xBB;
    memoria[1282] = 0x80;
    memoria[1283] = 0x96;
    memoria[1284] = 0x98;
    memoria[1285] = 0x00;
    memoria[1286] = 0xF7;
    memoria[1287] = 0xFB;
    memoria[1288] = 0x52;
    memoria[1289] = 0xE8;
    memoria[1290] = 0xF2;
    memoria[1291] = 0xFE;
    memoria[1292] = 0xFF;
    memoria[1293] = 0xFF;
    memoria[1294] = 0x58;
    memoria[1295] = 0xBA;
    memoria[1296] = 0x00;
    memoria[1297] = 0x00;
    memoria[1298] = 0x00;
    memoria[1299] = 0x00;
    memoria[1300] = 0xBB;
    memoria[1301] = 0x40;
    memoria[1302] = 0x42;
    memoria[1303] = 0x0F;
    memoria[1304] = 0x00;
    memoria[1305] = 0xF7;
    memoria[1306] = 0xFB;
    memoria[1307] = 0x52;
    memoria[1308] = 0xE8;
    memoria[1309] = 0xDF;
    memoria[1310] = 0xFE;
    memoria[1311] = 0xFF;
    memoria[1312] = 0xFF;
    memoria[1313] = 0x58;
    memoria[1314] = 0xBA;
    memoria[1315] = 0x00;
    memoria[1316] = 0x00;
    memoria[1317] = 0x00;
    memoria[1318] = 0x00;
    memoria[1319] = 0xBB;
    memoria[1320] = 0xA0;
    memoria[1321] = 0x86;
    memoria[1322] = 0x01;
    memoria[1323] = 0x00;
    memoria[1324] = 0xF7;
    memoria[1325] = 0xFB;
    memoria[1326] = 0x52;
    memoria[1327] = 0xE8;
    memoria[1328] = 0xCC;
    memoria[1329] = 0xFE;
    memoria[1330] = 0xFF;
    memoria[1331] = 0xFF;
    memoria[1332] = 0x58;
    memoria[1333] = 0xBA;
    memoria[1334] = 0x00;
    memoria[1335] = 0x00;
    memoria[1336] = 0x00;
    memoria[1337] = 0x00;
    memoria[1338] = 0xBB;
    memoria[1339] = 0x10;
    memoria[1340] = 0x27;
    memoria[1341] = 0x00;
    memoria[1342] = 0x00;
    memoria[1343] = 0xF7;
    memoria[1344] = 0xFB;
    memoria[1345] = 0x52;
    memoria[1346] = 0xE8;
    memoria[1347] = 0xB9;
    memoria[1348] = 0xFE;
    memoria[1349] = 0xFF;
    memoria[1350] = 0xFF;
    memoria[1351] = 0x58;
    memoria[1352] = 0xBA;
    memoria[1353] = 0x00;
    memoria[1354] = 0x00;
    memoria[1355] = 0x00;
    memoria[1356] = 0x00;
    memoria[1357] = 0xBB;
    memoria[1358] = 0xE8;
    memoria[1359] = 0x03;
    memoria[1360] = 0x00;
    memoria[1361] = 0x00;
    memoria[1362] = 0xF7;
    memoria[1363] = 0xFB;
    memoria[1364] = 0x52;
    memoria[1365] = 0xE8;
    memoria[1366] = 0xA6;
    memoria[1367] = 0xFE;
    memoria[1368] = 0xFF;
    memoria[1369] = 0xFF;
    memoria[1370] = 0x58;
    memoria[1371] = 0xBA;
    memoria[1372] = 0x00;
    memoria[1373] = 0x00;
    memoria[1374] = 0x00;
    memoria[1375] = 0x00;
    memoria[1376] = 0xBB;
    memoria[1377] = 0x64;
    memoria[1378] = 0x00;
    memoria[1379] = 0x00;
    memoria[1380] = 0x00;
    memoria[1381] = 0xF7;
    memoria[1382] = 0xFB;
    memoria[1383] = 0x52;
    memoria[1384] = 0xE8;
    memoria[1385] = 0x93;
    memoria[1386] = 0xFE;
    memoria[1387] = 0xFF;
    memoria[1388] = 0xFF;
    memoria[1389] = 0x58;
    memoria[1390] = 0xBA;
    memoria[1391] = 0x00;
    memoria[1392] = 0x00;
    memoria[1393] = 0x00;
    memoria[1394] = 0x00;
    memoria[1395] = 0xBB;
    memoria[1396] = 0x0A;
    memoria[1397] = 0x00;
    memoria[1398] = 0x00;
    memoria[1399] = 0x00;
    memoria[1400] = 0xF7;
    memoria[1401] = 0xFB;
    memoria[1402] = 0x52;
    memoria[1403] = 0xE8;
    memoria[1404] = 0x80;
    memoria[1405] = 0xFE;
    memoria[1406] = 0xFF;
    memoria[1407] = 0xFF;
    memoria[1408] = 0x58;
    memoria[1409] = 0xE8;
    memoria[1410] = 0x7A;
    memoria[1411] = 0xFE;
    memoria[1412] = 0xFF;
    memoria[1413] = 0xFF;
    memoria[1414] = 0xC3;
    memoria[1415] = 0x00;
    memoria[1416] = 0xFF;
    memoria[1417] = 0x15;
    memoria[1418] = 0x00;
    memoria[1419] = 0x10;
    memoria[1420] = 0x40;
    memoria[1421] = 0x00;
    memoria[1422] = 0x00;
    memoria[1423] = 0x00;
    memoria[1424] = 0xB9;
    memoria[1425] = 0x00;
    memoria[1426] = 0x00;
    memoria[1427] = 0x00;
    memoria[1428] = 0x00;
    memoria[1429] = 0xB3;
    memoria[1430] = 0x03;
    memoria[1431] = 0x51;
    memoria[1432] = 0x53;
    memoria[1433] = 0xE8;
    memoria[1434] = 0xA2;
    memoria[1435] = 0xFD;
    memoria[1436] = 0xFF;
    memoria[1437] = 0xFF;
    memoria[1438] = 0x5B;
    memoria[1439] = 0x59;
    memoria[1440] = 0x3C;
    memoria[1441] = 0x0D;
    memoria[1442] = 0x0F;
    memoria[1443] = 0x84;
    memoria[1444] = 0x34;
    memoria[1445] = 0x01;
    memoria[1446] = 0x00;
    memoria[1447] = 0x00;
    memoria[1448] = 0x3C;
    memoria[1449] = 0x08;
    memoria[1450] = 0x0F;
    memoria[1451] = 0x84;
    memoria[1452] = 0x94;
    memoria[1453] = 0x00;
    memoria[1454] = 0x00;
    memoria[1455] = 0x00;
    memoria[1456] = 0x3C;
    memoria[1457] = 0x2D;
    memoria[1458] = 0x0F;
    memoria[1459] = 0x84;
    memoria[1460] = 0x09;
    memoria[1461] = 0x01;
    memoria[1462] = 0x00;
    memoria[1463] = 0x00;
    memoria[1464] = 0x3C;
    memoria[1465] = 0x30;
    memoria[1466] = 0x7C;
    memoria[1467] = 0xDB;
    memoria[1468] = 0x3C;
    memoria[1469] = 0x39;
    memoria[1470] = 0x7F;
    memoria[1471] = 0xD7;
    memoria[1472] = 0x2C;
    memoria[1473] = 0x30;
    memoria[1474] = 0x80;
    memoria[1475] = 0xFB;
    memoria[1476] = 0x00;
    memoria[1477] = 0x74;
    memoria[1478] = 0xD0;
    memoria[1479] = 0x80;
    memoria[1480] = 0xFB;
    memoria[1481] = 0x02;
    memoria[1482] = 0x75;
    memoria[1483] = 0x0C;
    memoria[1484] = 0x81;
    memoria[1485] = 0xF9;
    memoria[1486] = 0x00;
    memoria[1487] = 0x00;
    memoria[1488] = 0x00;
    memoria[1489] = 0x00;
    memoria[1490] = 0x75;
    memoria[1491] = 0x04;
    memoria[1492] = 0x3C;
    memoria[1493] = 0x00;
    memoria[1494] = 0x74;
    memoria[1495] = 0xBF;
    memoria[1496] = 0x80;
    memoria[1497] = 0xFB;
    memoria[1498] = 0x03;
    memoria[1499] = 0x75;
    memoria[1500] = 0x0A;
    memoria[1501] = 0x3C;
    memoria[1502] = 0x00;
    memoria[1503] = 0x75;
    memoria[1504] = 0x04;
    memoria[1505] = 0xB3;
    memoria[1506] = 0x00;
    memoria[1507] = 0xEB;
    memoria[1508] = 0x02;
    memoria[1509] = 0xB3;
    memoria[1510] = 0x01;
    memoria[1511] = 0x81;
    memoria[1512] = 0xF9;
    memoria[1513] = 0xCC;
    memoria[1514] = 0xCC;
    memoria[1515] = 0xCC;
    memoria[1516] = 0x0C;
    memoria[1517] = 0x7F;
    memoria[1518] = 0xA8;
    memoria[1519] = 0x81;
    memoria[1520] = 0xF9;
    memoria[1521] = 0x34;
    memoria[1522] = 0x33;
    memoria[1523] = 0x33;
    memoria[1524] = 0xF3;
    memoria[1525] = 0x7C;
    memoria[1526] = 0xA0;
    memoria[1527] = 0x88;
    memoria[1528] = 0xC7;
    memoria[1529] = 0xB8;
    memoria[1530] = 0x0A;
    memoria[1531] = 0x00;
    memoria[1532] = 0x00;
    memoria[1533] = 0x00;
    memoria[1534] = 0xF7;
    memoria[1535] = 0xE9;
    memoria[1536] = 0x3D;
    memoria[1537] = 0x08;
    memoria[1538] = 0x00;
    memoria[1539] = 0x00;
    memoria[1540] = 0x80;
    memoria[1541] = 0x74;
    memoria[1542] = 0x11;
    memoria[1543] = 0x3D;
    memoria[1544] = 0xF8;
    memoria[1545] = 0xFF;
    memoria[1546] = 0xFF;
    memoria[1547] = 0x7F;
    memoria[1548] = 0x75;
    memoria[1549] = 0x13;
    memoria[1550] = 0x80;
    memoria[1551] = 0xFF;
    memoria[1552] = 0x07;
    memoria[1553] = 0x7E;
    memoria[1554] = 0x0E;
    memoria[1555] = 0xE9;
    memoria[1556] = 0x7F;
    memoria[1557] = 0xFF;
    memoria[1558] = 0xFF;
    memoria[1559] = 0xFF;
    memoria[1560] = 0x80;
    memoria[1561] = 0xFF;
    memoria[1562] = 0x08;
    memoria[1563] = 0x0F;
    memoria[1564] = 0x8F;
    memoria[1565] = 0x76;
    memoria[1566] = 0xFF;
    memoria[1567] = 0xFF;
    memoria[1568] = 0xFF;
    memoria[1569] = 0xB9;
    memoria[1570] = 0x00;
    memoria[1571] = 0x00;
    memoria[1572] = 0x00;
    memoria[1573] = 0x00;
    memoria[1574] = 0x88;
    memoria[1575] = 0xF9;
    memoria[1576] = 0x80;
    memoria[1577] = 0xFB;
    memoria[1578] = 0x02;
    memoria[1579] = 0x74;
    memoria[1580] = 0x04;
    memoria[1581] = 0x01;
    memoria[1582] = 0xC1;
    memoria[1583] = 0xEB;
    memoria[1584] = 0x03;
    memoria[1585] = 0x29;
    memoria[1586] = 0xC8;
    memoria[1587] = 0x91;
    memoria[1588] = 0x88;
    memoria[1589] = 0xF8;
    memoria[1590] = 0x51;
    memoria[1591] = 0x53;
    memoria[1592] = 0xE8;
    memoria[1593] = 0xC3;
    memoria[1594] = 0xFD;
    memoria[1595] = 0xFF;
    memoria[1596] = 0xFF;
    memoria[1597] = 0x5B;
    memoria[1598] = 0x59;
    memoria[1599] = 0xE9;
    memoria[1600] = 0x53;
    memoria[1601] = 0xFF;
    memoria[1602] = 0xFF;
    memoria[1603] = 0xFF;
    memoria[1604] = 0x80;
    memoria[1605] = 0xFB;
    memoria[1606] = 0x03;
    memoria[1607] = 0x0F;
    memoria[1608] = 0x84;
    memoria[1609] = 0x4A;
    memoria[1610] = 0xFF;
    memoria[1611] = 0xFF;
    memoria[1612] = 0xFF;
    memoria[1613] = 0x51;
    memoria[1614] = 0x53;
    memoria[1615] = 0xB0;
    memoria[1616] = 0x08;
    memoria[1617] = 0xE8;
    memoria[1618] = 0x7A;
    memoria[1619] = 0xFC;
    memoria[1620] = 0xFF;
    memoria[1621] = 0xFF;
    memoria[1622] = 0xB0;
    memoria[1623] = 0x20;
    memoria[1624] = 0xE8;
    memoria[1625] = 0x73;
    memoria[1626] = 0xFC;
    memoria[1627] = 0xFF;
    memoria[1628] = 0xFF;
    memoria[1629] = 0xB0;
    memoria[1630] = 0x08;
    memoria[1631] = 0xE8;
    memoria[1632] = 0x6C;
    memoria[1633] = 0xFC;
    memoria[1634] = 0xFF;
    memoria[1635] = 0xFF;
    memoria[1636] = 0x5B;
    memoria[1637] = 0x59;
    memoria[1638] = 0x80;
    memoria[1639] = 0xFB;
    memoria[1640] = 0x00;
    memoria[1641] = 0x75;
    memoria[1642] = 0x07;
    memoria[1643] = 0xB3;
    memoria[1644] = 0x03;
    memoria[1645] = 0xE9;
    memoria[1646] = 0x25;
    memoria[1647] = 0xFF;
    memoria[1648] = 0xFF;
    memoria[1649] = 0xFF;
    memoria[1650] = 0x80;
    memoria[1651] = 0xFB;
    memoria[1652] = 0x02;
    memoria[1653] = 0x75;
    memoria[1654] = 0x0F;
    memoria[1655] = 0x81;
    memoria[1656] = 0xF9;
    memoria[1657] = 0x00;
    memoria[1658] = 0x00;
    memoria[1659] = 0x00;
    memoria[1660] = 0x00;
    memoria[1661] = 0x75;
    memoria[1662] = 0x07;
    memoria[1663] = 0xB3;
    memoria[1664] = 0x03;
    memoria[1665] = 0xE9;
    memoria[1666] = 0x11;
    memoria[1667] = 0xFF;
    memoria[1668] = 0xFF;
    memoria[1669] = 0xFF;
    memoria[1670] = 0x89;
    memoria[1671] = 0xC8;
    memoria[1672] = 0xB9;
    memoria[1673] = 0x0A;
    memoria[1674] = 0x00;
    memoria[1675] = 0x00;
    memoria[1676] = 0x00;
    memoria[1677] = 0xBA;
    memoria[1678] = 0x00;
    memoria[1679] = 0x00;
    memoria[1680] = 0x00;
    memoria[1681] = 0x00;
    memoria[1682] = 0x3D;
    memoria[1683] = 0x00;
    memoria[1684] = 0x00;
    memoria[1685] = 0x00;
    memoria[1686] = 0x00;
    memoria[1687] = 0x7D;
    memoria[1688] = 0x08;
    memoria[1689] = 0xF7;
    memoria[1690] = 0xD8;
    memoria[1691] = 0xF7;
    memoria[1692] = 0xF9;
    memoria[1693] = 0xF7;
    memoria[1694] = 0xD8;
    memoria[1695] = 0xEB;
    memoria[1696] = 0x02;
    memoria[1697] = 0xF7;
    memoria[1698] = 0xF9;
    memoria[1699] = 0x89;
    memoria[1700] = 0xC1;
    memoria[1701] = 0x81;
    memoria[1702] = 0xF9;
    memoria[1703] = 0x00;
    memoria[1704] = 0x00;
    memoria[1705] = 0x00;
    memoria[1706] = 0x00;
    memoria[1707] = 0x0F;
    memoria[1708] = 0x85;
    memoria[1709] = 0xE6;
    memoria[1710] = 0xFE;
    memoria[1711] = 0xFF;
    memoria[1712] = 0xFF;
    memoria[1713] = 0x80;
    memoria[1714] = 0xFB;
    memoria[1715] = 0x02;
    memoria[1716] = 0x0F;
    memoria[1717] = 0x84;
    memoria[1718] = 0xDD;
    memoria[1719] = 0xFE;
    memoria[1720] = 0xFF;
    memoria[1721] = 0xFF;
    memoria[1722] = 0xB3;
    memoria[1723] = 0x03;
    memoria[1724] = 0xE9;
    memoria[1725] = 0xD6;
    memoria[1726] = 0xFE;
    memoria[1727] = 0xFF;
    memoria[1728] = 0xFF;
    memoria[1729] = 0x80;
    memoria[1730] = 0xFB;
    memoria[1731] = 0x03;
    memoria[1732] = 0x0F;
    memoria[1733] = 0x85;
    memoria[1734] = 0xCD;
    memoria[1735] = 0xFE;
    memoria[1736] = 0xFF;
    memoria[1737] = 0xFF;
    memoria[1738] = 0xB0;
    memoria[1739] = 0x2D;
    memoria[1740] = 0x51;
    memoria[1741] = 0x53;
    memoria[1742] = 0xE8;
    memoria[1743] = 0xFD;
    memoria[1744] = 0xFB;
    memoria[1745] = 0xFF;
    memoria[1746] = 0xFF;
    memoria[1747] = 0x5B;
    memoria[1748] = 0x59;
    memoria[1749] = 0xB3;
    memoria[1750] = 0x02;
    memoria[1751] = 0xE9;
    memoria[1752] = 0xBB;
    memoria[1753] = 0xFE;
    memoria[1754] = 0xFF;
    memoria[1755] = 0xFF;
    memoria[1756] = 0x80;
    memoria[1757] = 0xFB;
    memoria[1758] = 0x03;
    memoria[1759] = 0x0F;
    memoria[1760] = 0x84;
    memoria[1761] = 0xB2;
    memoria[1762] = 0xFE;
    memoria[1763] = 0xFF;
    memoria[1764] = 0xFF;
    memoria[1765] = 0x80;
    memoria[1766] = 0xFB;
    memoria[1767] = 0x02;
    memoria[1768] = 0x75;
    memoria[1769] = 0x0C;
    memoria[1770] = 0x81;
    memoria[1771] = 0xF9;
    memoria[1772] = 0x00;
    memoria[1773] = 0x00;
    memoria[1774] = 0x00;
    memoria[1775] = 0x00;
    memoria[1776] = 0x0F;
    memoria[1777] = 0x84;
    memoria[1778] = 0xA1;
    memoria[1779] = 0xFE;
    memoria[1780] = 0xFF;
    memoria[1781] = 0xFF;
    memoria[1782] = 0x51;
    memoria[1783] = 0xE8;
    memoria[1784] = 0x14;
    memoria[1785] = 0xFD;
    memoria[1786] = 0xFF;
    memoria[1787] = 0xFF;
    memoria[1788] = 0x59;
    memoria[1789] = 0x89;
    memoria[1790] = 0xC8;
    memoria[1791] = 0xC3;
    topeMemoria = 1792; // 0x700

    cargarByte(0XBF, memoria, &topeMemoria); // MOV EDI, ...
    cargarInt(0x00, memoria, &topeMemoria);  // estos 0s se corregiran en 2034

    bloque(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, 0, &topeMemoria, memoria, &contadorVars);
    if ((*simbolo) == PUNTO)
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
    else
        mensajeErr(f, 2, cadenaSimbolo);

    int distanciaHasta0x588 = 0x588 - (topeMemoria + 5);
    cargarByte(0XE9, memoria, &topeMemoria); // JMP
    cargarInt(distanciaHasta0x588, memoria, &topeMemoria);

    int ubicacionDeVars = 0x401000 + (topeMemoria - 0x200);
    cargarIntEn(ubicacionDeVars, memoria, 1793); // 2034

    for (int i = 0; i < contadorVars; i++)
    {
        cargarInt(0x00, memoria, &topeMemoria);
    }

    cargarIntEn(topeMemoria - 0x200, memoria, 416);

    int fileAligment = 512;
    while (topeMemoria % fileAligment != 0)
    {
        cargarByte(0X00, memoria, &topeMemoria);
    }

    int sizeOfCodeSection = topeMemoria - 0x200;
    int sizeOfRawData = topeMemoria - 0x200;
    cargarIntEn(sizeOfCodeSection, memoria, 188);
    cargarIntEn(sizeOfRawData, memoria, 424);

    int sectionAlignment = 0x1000;
    int sizeOfImage = (2 + sizeOfCodeSection / sectionAlignment) * sectionAlignment;
    int baseOfData = (2 + sizeOfRawData / sectionAlignment) * sectionAlignment;
    cargarIntEn(sizeOfImage, memoria, 240);
    cargarIntEn(baseOfData, memoria, 208);

    fwrite(memoria, sizeof(unsigned char), topeMemoria, fb);
    fclose(fb);
    printf("Compilacion exitosa\n");
    // fclose(fl);
    // remove(nombreArchivo);
}
void bloque(FILE *f, cadena_t restante, simbolo_t *simbolo, cadena_t cadenaSimbolo, int *contadorRenglon, tabla_t tablaSimb, int base, int *topeMemoria, vector_t memoria, int *contadorVars)
{
    cargarByte(0XE9, memoria, topeMemoria);
    cargarInt(0x00, memoria, topeMemoria);
    int origenSalto = *topeMemoria;

    int desplazamiento = 0;

    if ((*simbolo) == CONST)
    {
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        //
        if ((*simbolo) == IDENT)
        {

            if (busqueda(tablaSimb, base + desplazamiento - 1, base, cadenaSimbolo) == -1)
            {
                strcpy(tablaSimb[base + desplazamiento].nombre, cadenaSimbolo);
                tablaSimb[base + desplazamiento].tipo = CONST;
            }
            else
            {
                mensajeErr(f, 17, cadenaSimbolo);
            }
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        }
        else
            mensajeErr(f, 3, cadenaSimbolo);
        //
        if ((*simbolo) == IGUAL){
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        }else{
            mensajeErr(f, 5, cadenaSimbolo);
        }
        //*
        if ((*simbolo) == MENOS)
        {
            cadena_t simboloNeg;
            //desplazamiento++;
            strcpy(simboloNeg,cadenaSimbolo);
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            if ((*simbolo) == NUMERO)
            {
                strcat(simboloNeg,cadenaSimbolo);
                strcpy(cadenaSimbolo,simboloNeg);
              //  printf(cadenaSimbolo);
                tablaSimb[base + desplazamiento].valor = atoi(cadenaSimbolo);
                desplazamiento++;
                escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            }
            else{
                mensajeErr(f, 5, cadenaSimbolo);
            }
        }

        //
        else if ((*simbolo) == NUMERO)
        {
            //printf("ESTOY ACA\n");
            tablaSimb[base + desplazamiento].valor = atoi(cadenaSimbolo);
            desplazamiento++;
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        }
        else
            mensajeErr(f, 5, cadenaSimbolo);
        //
        while ((*simbolo) == COMA)
        {
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            //
            if ((*simbolo) == IDENT)
            {
                if (busqueda(tablaSimb, base + desplazamiento - 1, base, cadenaSimbolo) == -1)
                {
                    strcpy(tablaSimb[base + desplazamiento].nombre, cadenaSimbolo);
                    tablaSimb[base + desplazamiento].tipo = CONST;
                }
                else
                {
                    mensajeErr(f, 17, cadenaSimbolo);
                }
                escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            }
            else
                mensajeErr(f, 3, cadenaSimbolo);
            //
            if ((*simbolo) == IGUAL)
                escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            else
                mensajeErr(f, 4, cadenaSimbolo);
            //
            if ((*simbolo) == NUMERO)
            {
                tablaSimb[base + desplazamiento].valor = atoi(cadenaSimbolo);
                desplazamiento++;
                escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            }
            else
                mensajeErr(f, 5, cadenaSimbolo);
        }
        if ((*simbolo) == PUNTOYCOMA)
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        else
            mensajeErr(f, 6, cadenaSimbolo);
    }
    if ((*simbolo) == VAR)
    {
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        //
        if ((*simbolo) == IDENT)
        {
            if (busqueda(tablaSimb, base + desplazamiento - 1, base, cadenaSimbolo) == -1)
            {
                strcpy(tablaSimb[base + desplazamiento].nombre, cadenaSimbolo);
                tablaSimb[base + desplazamiento].tipo = VAR;
                tablaSimb[base + desplazamiento].valor = 4 * (*contadorVars);
                desplazamiento++;
                (*contadorVars)++;
            }
            else
            {
                mensajeErr(f, 17, cadenaSimbolo);
            }
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        }
        else
            mensajeErr(f, 3, cadenaSimbolo);
        //
        while ((*simbolo) == COMA)
        {
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            //
            if ((*simbolo) == IDENT)
            {
                if (busqueda(tablaSimb, base + desplazamiento - 1, base, cadenaSimbolo) == -1)
                {
                    strcpy(tablaSimb[base + desplazamiento].nombre, cadenaSimbolo);
                    tablaSimb[base + desplazamiento].tipo = VAR;
                    tablaSimb[base + desplazamiento].valor = 4 * (*contadorVars);
                    desplazamiento++;
                    (*contadorVars)++;
                }
                else
                {
                    mensajeErr(f, 17, cadenaSimbolo);
                }
                escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            }
            else
                mensajeErr(f, 3, cadenaSimbolo);
        }
        if ((*simbolo) == PUNTOYCOMA)
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        else
            mensajeErr(f, 6, cadenaSimbolo);
    }
    while ((*simbolo) == PROCEDURE)
    {
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        //
        if ((*simbolo) == IDENT)
        {
            if (busqueda(tablaSimb, base + desplazamiento - 1, base, cadenaSimbolo) == -1)
            {
                strcpy(tablaSimb[base + desplazamiento].nombre, cadenaSimbolo);
                tablaSimb[base + desplazamiento].tipo = PROCEDURE;
                tablaSimb[base + desplazamiento].valor = *topeMemoria;
                desplazamiento++;
            }
            else
            {
                mensajeErr(f, 17, cadenaSimbolo);
            }
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        }
        else
            mensajeErr(f, 3, cadenaSimbolo);
        //
        if ((*simbolo) == PUNTOYCOMA)
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        else
            mensajeErr(f, 7, cadenaSimbolo);
        bloque(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base + desplazamiento, topeMemoria, memoria, contadorVars);
        cargarByte(0xC3, memoria, topeMemoria); // RET
        if ((*simbolo) == PUNTOYCOMA)
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        else
            mensajeErr(f, 7, cadenaSimbolo);
    }
    int distanciaHastaAca = *topeMemoria - origenSalto;
    cargarIntEn(distanciaHastaAca, memoria, origenSalto - 4);
    proposicion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
}
void proposicion(FILE *f, cadena_t restante, simbolo_t *simbolo, cadena_t cadenaSimbolo, int *contadorRenglon, tabla_t tablaSimb, int base, int desplazamiento, int *topeMemoria, vector_t memoria)
{
    int p;
    int distanciaRutina;
    int distanciaSalto;
    int distanciaCiclo;
    int origenSalto;
    int origenCiclo;
    int ubicacionDeCadena;
    switch (*simbolo)
    {
    case IDENT:
        p = busqueda(tablaSimb, base + desplazamiento - 1, 0, cadenaSimbolo);
        if (p == -1)
        {
            mensajeErr(f, 18, cadenaSimbolo);
        }
        else
        {
            if (tablaSimb[p].tipo != VAR)
            {
                mensajeErr(f, 19, cadenaSimbolo);
            }
        }
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        if ((*simbolo) == ASIGNACION){
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        }else
            mensajeErr(f, 8, cadenaSimbolo);
        expresion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
        cargarByte(0x58, memoria, topeMemoria); // POP EAX
        cargarByte(0x89, memoria, topeMemoria); // MOV [EDI+...], EAX
        cargarByte(0x87, memoria, topeMemoria);
        cargarInt(tablaSimb[p].valor, memoria, topeMemoria);
        break;

    case CALL:

        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);

        if ((*simbolo) == IDENT)
        {
            p = busqueda(tablaSimb, base + desplazamiento - 1, 0, cadenaSimbolo);

            if (p == -1)
            {

                mensajeErr(f, 18, cadenaSimbolo);
            }
            else
            {
                if (tablaSimb[p].tipo != PROCEDURE)
                {
                    mensajeErr(f, 21, cadenaSimbolo);
                }
            }
            distanciaRutina = tablaSimb[p].valor - (*topeMemoria + 5);

            cargarByte(0xE8, memoria, topeMemoria); // CALL
            cargarInt(distanciaRutina, memoria, topeMemoria);
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        }
        else
            mensajeErr(f, 3, cadenaSimbolo);
        break;

    case BEGIN:
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        proposicion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
        while (*simbolo == PUNTOYCOMA)
        {
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            proposicion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
        }
        if ((*simbolo) == END)
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        else
            mensajeErr(f, 12, cadenaSimbolo);
        break;
    case IF:
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        condicion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
        origenSalto = *topeMemoria;
        if ((*simbolo) == THEN)
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        else
            mensajeErr(f, 13, cadenaSimbolo);
        proposicion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
        distanciaSalto = *topeMemoria - origenSalto;
        cargarIntEn(distanciaSalto, memoria, origenSalto - 4);
        break;
    case WHILE:
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        origenCiclo = *topeMemoria;
        condicion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
        origenSalto = *topeMemoria;
        if ((*simbolo) == DO)
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        else
            mensajeErr(f, 14, cadenaSimbolo);
        proposicion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);

        distanciaCiclo = origenCiclo - (*topeMemoria + 5);
        cargarByte(0xE9, memoria, topeMemoria); // JMP
        cargarInt(distanciaCiclo, memoria, topeMemoria);

        distanciaSalto = *topeMemoria - origenSalto;
        cargarIntEn(distanciaSalto, memoria, origenSalto - 4);
        break;
    case READLN:
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        if ((*simbolo) == ABREPARENTESIS)
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        else
            mensajeErr(f, 15, cadenaSimbolo);

        if ((*simbolo) == IDENT)
        {
            p = busqueda(tablaSimb, base + desplazamiento - 1, 0, cadenaSimbolo);
            if (p == -1)
            {

                mensajeErr(f, 18, cadenaSimbolo);
            }
            else
            {
                if (tablaSimb[p].tipo != VAR)
                {
                    mensajeErr(f, 19, cadenaSimbolo);
                }
            }
            distanciaRutina = 0x0590 - (*topeMemoria + 5);

            cargarByte(0xE8, memoria, topeMemoria); // CALL
            cargarInt(distanciaRutina, memoria, topeMemoria);

            cargarByte(0x89, memoria, topeMemoria); // MOV [EDI+...], EAX
            cargarByte(0x87, memoria, topeMemoria);
            cargarInt(tablaSimb[p].valor, memoria, topeMemoria);
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        }
        else
            mensajeErr(f, 3, cadenaSimbolo);
        while (*simbolo == COMA)
        {
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            if ((*simbolo) == IDENT)
            {
                p = busqueda(tablaSimb, base + desplazamiento - 1, 0, cadenaSimbolo);
                if (p == -1)
                {

                    mensajeErr(f, 18, cadenaSimbolo);
                }
                else
                {
                    if (tablaSimb[p].tipo != VAR)
                    {
                        mensajeErr(f, 19, cadenaSimbolo);
                    }
                }
                distanciaRutina = 0x0590 - (*topeMemoria + 5);

                cargarByte(0xE8, memoria, topeMemoria); // CALL
                cargarInt(distanciaRutina, memoria, topeMemoria);

                cargarByte(0x89, memoria, topeMemoria); // MOV [EDI+...], EAX
                cargarByte(0x87, memoria, topeMemoria);
                cargarInt(tablaSimb[p].valor, memoria, topeMemoria);
                escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            }
            else
                mensajeErr(f, 3, cadenaSimbolo);
        }
        if (*simbolo == CIERRAPARENTESIS)
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        else
            mensajeErr(f, 16, cadenaSimbolo);
        break;
    case WRITE:
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        if (*simbolo == ABREPARENTESIS)
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        else
            mensajeErr(f, 15, cadenaSimbolo);
        if (*simbolo == CADENA)
        {
            ubicacionDeCadena = 0x401000 + (*topeMemoria - 0x200) + 15;

            cargarByte(0xB8, memoria, topeMemoria); // MOV EAX,...
            cargarInt(ubicacionDeCadena, memoria, topeMemoria);

            distanciaRutina = 0x03E0 - (*topeMemoria + 5);

            cargarByte(0xE8, memoria, topeMemoria); // CALL
            cargarInt(distanciaRutina, memoria, topeMemoria);
            cargarByte(0xE9, memoria, topeMemoria); // JMP
            cargarInt(strlen(cadenaSimbolo) - 1, memoria, topeMemoria);
            for (int i = 1; i < strlen(cadenaSimbolo) - 1; i++)
            {
                cargarByte(cadenaSimbolo[i], memoria, topeMemoria); //
            }
            cargarByte(0, memoria, topeMemoria);

            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        }
        else
        {
            expresion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
            cargarByte(0x58, memoria, topeMemoria); // POP EAX

            distanciaRutina = 0x0420 - (*topeMemoria + 5);

            cargarByte(0xE8, memoria, topeMemoria); // CALL
            cargarInt(distanciaRutina, memoria, topeMemoria);
        }
        while (*simbolo == COMA)
        {
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            if (*simbolo == CADENA)
            {
                ubicacionDeCadena = 0x401000 + (*topeMemoria - 0x200) + 15;

                cargarByte(0xB8, memoria, topeMemoria); // MOV EAX,...
                cargarInt(ubicacionDeCadena, memoria, topeMemoria);

                distanciaRutina = 0x03E0 - (*topeMemoria + 5);

                cargarByte(0xE8, memoria, topeMemoria); // CALL
                cargarInt(distanciaRutina, memoria, topeMemoria);
                cargarByte(0xE9, memoria, topeMemoria); // JMP
                cargarInt(strlen(cadenaSimbolo) - 1, memoria, topeMemoria);
                for (int i = 1; i < strlen(cadenaSimbolo) - 1; i++)
                {
                    cargarByte(cadenaSimbolo[i], memoria, topeMemoria); //
                }
                cargarByte(0, memoria, topeMemoria);

                escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            }
            else
            {
                expresion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
                cargarByte(0x58, memoria, topeMemoria); // POP EAX

                distanciaRutina = 0x0420 - (*topeMemoria + 5);

                cargarByte(0xE8, memoria, topeMemoria); // CALL
                cargarInt(distanciaRutina, memoria, topeMemoria);
            }
        }
        if (*simbolo == CIERRAPARENTESIS)
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        else
            mensajeErr(f, 16, cadenaSimbolo);
        break;
    case WRITELN:
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        if (*simbolo == ABREPARENTESIS)
        {
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);

            if (*simbolo == CADENA)
            {
                ubicacionDeCadena = 0x401000 + (*topeMemoria - 0x200) + 15;

                cargarByte(0xB8, memoria, topeMemoria); // MOV EAX,...
                cargarInt(ubicacionDeCadena, memoria, topeMemoria);

                distanciaRutina = 0x03E0 - (*topeMemoria + 5);

                cargarByte(0xE8, memoria, topeMemoria); // CALL
                cargarInt(distanciaRutina, memoria, topeMemoria);
                cargarByte(0xE9, memoria, topeMemoria); // JMP
                cargarInt(strlen(cadenaSimbolo) - 1, memoria, topeMemoria);
                for (int i = 1; i < strlen(cadenaSimbolo) - 1; i++)
                {
                    cargarByte(cadenaSimbolo[i], memoria, topeMemoria); //
                }
                cargarByte(0, memoria, topeMemoria);

                escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            }
            else
            {
                expresion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
                cargarByte(0x58, memoria, topeMemoria); // POP EAX

                distanciaRutina = 0x0420 - (*topeMemoria + 5);

                cargarByte(0xE8, memoria, topeMemoria); // CALL
                cargarInt(distanciaRutina, memoria, topeMemoria);
            }
            while (*simbolo == COMA)
            {
                escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
                if (*simbolo == CADENA)
                {
                    ubicacionDeCadena = 0x401000 + (*topeMemoria - 0x200) + 15;

                    cargarByte(0xB8, memoria, topeMemoria); // MOV EAX,...
                    cargarInt(ubicacionDeCadena, memoria, topeMemoria);

                    distanciaRutina = 0x03E0 - (*topeMemoria + 5);

                    cargarByte(0xE8, memoria, topeMemoria); // CALL
                    cargarInt(distanciaRutina, memoria, topeMemoria);
                    cargarByte(0xE9, memoria, topeMemoria); // JMP
                    cargarInt(strlen(cadenaSimbolo) - 1, memoria, topeMemoria);
                    for (int i = 1; i < strlen(cadenaSimbolo) - 1; i++)
                    {
                        cargarByte(cadenaSimbolo[i], memoria, topeMemoria); //
                    }
                    cargarByte(0, memoria, topeMemoria);

                    escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
                }
                else
                {
                    expresion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);

                    cargarByte(0x58, memoria, topeMemoria); // POP EAX

                    distanciaRutina = 0x0420 - (*topeMemoria + 5);

                    cargarByte(0xE8, memoria, topeMemoria); // CALL
                    cargarInt(distanciaRutina, memoria, topeMemoria);
                }
            }
            if (*simbolo == CIERRAPARENTESIS)
                escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            else
                mensajeErr(f, 16, cadenaSimbolo);
        }
        distanciaRutina = 0x0410 - (*topeMemoria + 5);

        cargarByte(0xE8, memoria, topeMemoria); // CALL
        cargarInt(distanciaRutina, memoria, topeMemoria);
    }
}
void condicion(FILE *f, cadena_t restante, simbolo_t *simbolo, cadena_t cadenaSimbolo, int *contadorRenglon, tabla_t tablaSimb, int base, int desplazamiento, int *topeMemoria, vector_t memoria)
{
    if ((*simbolo) == ODD)
    {
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        expresion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
        cargarByte(0x58, memoria, topeMemoria); // POP EAX
        cargarByte(0xA8, memoria, topeMemoria); // TEST AL, 01
        cargarByte(0x01, memoria, topeMemoria);
        cargarByte(0x7B, memoria, topeMemoria); // JPO 05
        cargarByte(0x05, memoria, topeMemoria);
        cargarByte(0xE9, memoria, topeMemoria); // JMP 00
        cargarInt(0x00, memoria, topeMemoria);
    }
    else
    {
        expresion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
        simbolo_t simboloAux = *simbolo;
        switch (*simbolo)
        {
        case IGUAL:
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            break;
        case DISTINTO:
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            break;
        case MAYOR:
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            break;
        case MAYORIGUAL:
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            break;
        case MENOR:
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            break;
        case MENORIGUAL:
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            break;
        default:
            mensajeErr(f, 9, cadenaSimbolo);
        }
        expresion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);

        cargarByte(0x58, memoria, topeMemoria); // POP EAX
        cargarByte(0x5B, memoria, topeMemoria); // POP EBX
        cargarByte(0x39, memoria, topeMemoria); // CMP EBX, EAX
        cargarByte(0xC3, memoria, topeMemoria);
        switch (simboloAux)
        {
        case IGUAL:
            cargarByte(0x74, memoria, topeMemoria);
            break;
        case DISTINTO:
            cargarByte(0x75, memoria, topeMemoria);
            break;
        case MAYOR:
            cargarByte(0x7F, memoria, topeMemoria);
            ;
            break;
        case MAYORIGUAL:
            cargarByte(0x7D, memoria, topeMemoria);
            break;
        case MENOR:
            cargarByte(0x7C, memoria, topeMemoria);
            break;
        case MENORIGUAL:
            cargarByte(0x7E, memoria, topeMemoria);
            break;
        }
        cargarByte(0x05, memoria, topeMemoria);
        cargarByte(0xE9, memoria, topeMemoria); // JMP 00
        cargarInt(0x00, memoria, topeMemoria);
    }
}
void expresion(FILE *f, cadena_t restante, simbolo_t *simbolo, cadena_t cadenaSimbolo, int *contadorRenglon, tabla_t tablaSimb, int base, int desplazamiento, int *topeMemoria, vector_t memoria)
{
    simbolo_t simboloAux = *simbolo;
    switch (*simbolo)
    {
    case MAS:
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        break;
    case MENOS:
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
    }
    termino(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
    if (simboloAux == MENOS)
    {
        cargarByte(0x58, memoria, topeMemoria); // POP EAX
        cargarByte(0xF7, memoria, topeMemoria); // NEG EBX
        cargarByte(0xD8, memoria, topeMemoria);
        cargarByte(0x50, memoria, topeMemoria); // PUSH EAX
    }

    while (*simbolo == MAS || *simbolo == MENOS)
    {
        simbolo_t simboloAux2 = *simbolo;
        switch (*simbolo)
        {
        case MAS:
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            break;
        case MENOS:
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        }
        termino(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
        switch (simboloAux2)
        {
        case MAS:
            cargarByte(0x58, memoria, topeMemoria); // POP EAX
            cargarByte(0x5B, memoria, topeMemoria); // POP EBX
            cargarByte(0x01, memoria, topeMemoria); // ADD EAX, EBX
            cargarByte(0xD8, memoria, topeMemoria);
            cargarByte(0x50, memoria, topeMemoria); // PUSH EAX
            break;
        case MENOS:
            cargarByte(0x58, memoria, topeMemoria); // POP EAX
            cargarByte(0x5B, memoria, topeMemoria); // POP EBX
            cargarByte(0x93, memoria, topeMemoria); // XCHG EAX, EBX
            cargarByte(0x29, memoria, topeMemoria); // SUB EAX, EBX
            cargarByte(0xD8, memoria, topeMemoria);
            cargarByte(0x50, memoria, topeMemoria); // PUSH EAX
        }
    }
}
void termino(FILE *f, cadena_t restante, simbolo_t *simbolo, cadena_t cadenaSimbolo, int *contadorRenglon, tabla_t tablaSimb, int base, int desplazamiento, int *topeMemoria, vector_t memoria)
{
    factor(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
    while (*simbolo == MULTIPLICACION || *simbolo == DIVISION)
    {
        simbolo_t simboloAux = *simbolo;
        switch (*simbolo)
        {
        case MULTIPLICACION:
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            break;
        case DIVISION:
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        }
        factor(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
        switch (simboloAux)
        {
        case MULTIPLICACION:
            cargarByte(0x58, memoria, topeMemoria); // POP EAX
            cargarByte(0x5B, memoria, topeMemoria); // POP EBX
            cargarByte(0xF7, memoria, topeMemoria); // IMUL EBX
            cargarByte(0xEB, memoria, topeMemoria);
            cargarByte(0x50, memoria, topeMemoria); // PUSH EAX
            break;
        case DIVISION:
            cargarByte(0x58, memoria, topeMemoria); // POP EAX
            cargarByte(0x5B, memoria, topeMemoria); // POP EBX
            cargarByte(0x93, memoria, topeMemoria); // XCHG EAX, EBX
            cargarByte(0x99, memoria, topeMemoria); // CDQ (EAX DE 32 A 64 BITS, SI EAX ES NEGATIVO CDQ GARANTIZA RESULTADO NEGATIVO)
            cargarByte(0xF7, memoria, topeMemoria); // IDIV EBX (EAX = EDX:EAX / EBX)
            cargarByte(0xFB, memoria, topeMemoria);
            cargarByte(0x50, memoria, topeMemoria); // PUSH EAX
        }
    }
}
void factor(FILE *f, cadena_t restante, simbolo_t *simbolo, cadena_t cadenaSimbolo, int *contadorRenglon, tabla_t tablaSimb, int base, int desplazamiento, int *topeMemoria, vector_t memoria)
{
    int p;
    switch (*simbolo)
    {
    case IDENT:
        p = busqueda(tablaSimb, base + desplazamiento - 1, 0, cadenaSimbolo);
        if (p == -1)
        {
            printf("estoy aca\n");
            mensajeErr(f, 18, cadenaSimbolo);
        }
        else
        {
            if (tablaSimb[p].tipo == PROCEDURE)
            {
                mensajeErr(f, 20, cadenaSimbolo);
            }
            else
            {
                if (tablaSimb[p].tipo == VAR)
                {
                    cargarByte(0x8B, memoria, topeMemoria); // MOV EAX, [EDI + ...]
                    cargarByte(0x87, memoria, topeMemoria);
                    cargarInt(tablaSimb[p].valor, memoria, topeMemoria);
                    cargarByte(0x50, memoria, topeMemoria); // PUSH EAX
                }
                else // es CONST
                {
                    cargarByte(0xB8, memoria, topeMemoria); // MOV EAX, ...
                    cargarInt(tablaSimb[p].valor, memoria, topeMemoria);
                    cargarByte(0x50, memoria, topeMemoria); // PUSH EAX
                }
            }
        }
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        break;

    case NUMERO:
        cargarByte(0xB8, memoria, topeMemoria); // MOV EAX, ...
        cargarInt(atoi(cadenaSimbolo), memoria, topeMemoria);
        cargarByte(0x50, memoria, topeMemoria); // PUSH EAX
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        break;
    case ABREPARENTESIS:
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        expresion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
        if ((*simbolo) == CIERRAPARENTESIS)
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        else
            mensajeErr(f, 11, cadenaSimbolo);
        break;

    case SQR:
       // printf("estoy aca1\n");
        escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
        if((*simbolo)== ABREPARENTESIS){
            escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            expresion(f, restante, simbolo, cadenaSimbolo, contadorRenglon, tablaSimb, base, desplazamiento, topeMemoria, memoria);
            // printf("estoy aca2\n");
            cargarByte(0x5B, memoria, topeMemoria); // POP EBX
            cargarByte(0xB8, memoria, topeMemoria); // MOV EAX X
            cargarInt(0x00, memoria, topeMemoria);
            cargarByte(0x01, memoria, topeMemoria); // ADD EAX, EBX
            cargarByte(0xD8, memoria, topeMemoria);
            cargarByte(0xF7, memoria, topeMemoria); // IMUL EBX
            cargarByte(0xEB, memoria, topeMemoria);
            cargarByte(0x50, memoria, topeMemoria); // PUSH EAX
            if((*simbolo)== CIERRAPARENTESIS){
                // printf("estoy aca3\n");
                escanear(f, restante, simbolo, cadenaSimbolo, contadorRenglon);
            }else mensajeErr(f, 11, cadenaSimbolo);
        } else mensajeErr(f, 23, cadenaSimbolo);
        break;
    default:
        //printf("estoy aca4\n");
        mensajeErr(f, 10, cadenaSimbolo);
    }
}
/*
Recibe una cadena cad del tipo cadena_t y con largo máximo MAXCHAR. Se "corre" toda la cadena una
posición hacia la izquierda consuminedo el primer caracter de la misma.
*/
void consumirChar(cadena_t cadena)
{
    for (int i = 1; i < MAX_CAD; i++)
    {
        cadena[i - 1] = cadena[i];
    }
}
void cargarByte(unsigned char dato, vector_t memoria, int *topeMemoria)
{
    memoria[(*topeMemoria)++] = dato;
}
void cargarInt(int dato, vector_t memoria, int *topeMemoria)
{                                          // 12345678
    unsigned char b1 = (dato << 24) >> 24; // 78
    unsigned char b2 = (dato << 16) >> 24; // 56
    unsigned char b3 = (dato << 8) >> 24;  // 34
    unsigned char b4 = dato >> 24;         // 12
    memoria[(*topeMemoria)++] = b1;        // 78
    memoria[(*topeMemoria)++] = b2;        // 56
    memoria[(*topeMemoria)++] = b3;        // 34
    memoria[(*topeMemoria)++] = b4;        // 12
}
void cargarIntEn(int dato, vector_t memoria, int posicion)
{                                          // 12345678
    unsigned char b1 = (dato << 24) >> 24; // 78
    unsigned char b2 = (dato << 16) >> 24; // 56
    unsigned char b3 = (dato << 8) >> 24;  // 34
    unsigned char b4 = dato >> 24;         // 12
    memoria[posicion] = b1;                // 78
    memoria[posicion + 1] = b2;            // 56
    memoria[posicion + 2] = b3;            // 34
    memoria[posicion + 3] = b4;            // 12
}
/*
Función auxiliar utilizada dentro de la función escanear. Convierte una cadena completa a letras mayúsculas
*/
void aMayuscula(cadena_t cadena)
{
    for (int i = 0; i < strlen(cadena); i++)
    {
        cadena[i] = toupper(cadena[i]);
    }
}
/*


*/
void escanear(FILE *f, cadena_t restante, simbolo_t *simbolo, cadena_t cadenaSimbolo, int *contadorRenglon)
{
    cadenaSimbolo[0] = FIN_CAD; // Como es una cadena sin utilizar, se inicializa como vacía
    int i = 0;

    while (restante != NULL && (restante[0] == FIN_CAD || isspace(restante[0])) && (*simbolo) != FINARCH)
    {
        if (restante[0] != FIN_CAD)
            consumirChar(restante);

        if (restante[0] == FIN_CAD)
        {
            if (fgets(restante, MAX_CAD, f) != NULL)
            {
                printf("%3d: ", *contadorRenglon);
                printf("%s", restante);
                (*contadorRenglon)++;
            }
            else
            {
                *simbolo = FINARCH;
            }
        }
    }

    // Clasificación
    if (*simbolo != FINARCH)
    {
        if (isalpha(restante[0])) // Si es alfabético
        {
            cadena_t cadenaAux;
            do
            {
                cadenaSimbolo[i] = restante[0];
                cadenaSimbolo[i + 1] = FIN_CAD;
                i++;
                consumirChar(restante);
            } while (isalnum(restante[0])); // Mientras sea alfabético o numérico

            strcpy(cadenaAux, cadenaSimbolo);
            aMayuscula(cadenaAux);

            if (strcmp(cadenaAux, "CONST") == 0)
            {
                *simbolo = CONST;
            }
            else if (strcmp(cadenaAux, "VAR") == 0)
            {
                *simbolo = VAR;
            }
            else if (strcmp(cadenaAux, "PROCEDURE") == 0)
            {
                *simbolo = PROCEDURE;
            }
            else if (strcmp(cadenaAux, "CALL") == 0)
            {
                *simbolo = CALL;
            }
            else if (strcmp(cadenaAux, "BEGIN") == 0)
            {
                *simbolo = BEGIN;
            }
            else if (strcmp(cadenaAux, "END") == 0)
            {
                *simbolo = END;
            }
            else if (strcmp(cadenaAux, "IF") == 0)
            {
                *simbolo = IF;
            }
            else if (strcmp(cadenaAux, "THEN") == 0)
            {
                *simbolo = THEN;
            }
            else if (strcmp(cadenaAux, "WHILE") == 0)
            {
                *simbolo = WHILE;
            }
            else if (strcmp(cadenaAux, "DO") == 0)
            {
                *simbolo = DO;
            }
            else if (strcmp(cadenaAux, "READLN") == 0)
            {
                *simbolo = READLN;
            }
            else if (strcmp(cadenaAux, "WRITE") == 0)
            {
                *simbolo = WRITE;
            }
            else if (strcmp(cadenaAux, "WRITELN") == 0)
            {
                *simbolo = WRITELN;
            }
            else if (strcmp(cadenaAux, "ODD") == 0)
            {
                *simbolo = ODD;
            }
            else if (strcmp(cadenaAux, "SQR") == 0)
            {
                *simbolo = SQR;
            }
            else
            {
                *simbolo = IDENT;
            }
        }
        else if (isdigit(restante[0])) // Si es dígito 0-9
        {
            do
            {
                cadenaSimbolo[i] = restante[0];
                cadenaSimbolo[i + 1] = FIN_CAD;
                i++;
                consumirChar(restante);
            } while (isdigit(restante[0])); // Mientras sea dígito

            // clasificar el numero(NUMERO o NULO)
            *simbolo = NUMERO;
        }
        else
        {
            switch (restante[0])
            {
            case '\'':
                do
                {
                    cadenaSimbolo[i] = restante[0];
                    cadenaSimbolo[i + 1] = FIN_CAD;
                    i++;
                    consumirChar(restante);
                } while (restante[0] != '\'' && restante[0] != '\0');
                if (restante[0] == '\'')
                {
                    cadenaSimbolo[i] = restante[0];
                    cadenaSimbolo[i + 1] = FIN_CAD;
                    i++;
                    consumirChar(restante);
                    *simbolo = CADENA;
                }
                else
                {
                    *simbolo = NULO;
                }
                break;

            case ':':
                if (restante[1] == '=')
                {
                    cadenaSimbolo[0] = ':';
                    cadenaSimbolo[1] = '=';
                    cadenaSimbolo[2] = FIN_CAD;
                    *simbolo = ASIGNACION;
                    consumirChar(restante);
                    consumirChar(restante);
                }
                else
                {
                    cadenaSimbolo[0] = ':';
                    cadenaSimbolo[1] = FIN_CAD;
                    *simbolo = NULO;
                    consumirChar(restante);
                }
                break;

            case '=':
                cadenaSimbolo[0] = '=';
                cadenaSimbolo[1] = FIN_CAD;
                *simbolo = IGUAL;
                consumirChar(restante);
                break;

            case '<':
                if (restante[1] == '>')
                {
                    cadenaSimbolo[0] = '<';
                    cadenaSimbolo[1] = '>';
                    cadenaSimbolo[2] = FIN_CAD;
                    *simbolo = DISTINTO;
                    consumirChar(restante);
                    consumirChar(restante);
                }
                else if (restante[1] == '=')
                {
                    cadenaSimbolo[0] = '<';
                    cadenaSimbolo[1] = '=';
                    cadenaSimbolo[2] = FIN_CAD;
                    *simbolo = MENORIGUAL;
                    consumirChar(restante);
                    consumirChar(restante);
                }
                else
                {
                    cadenaSimbolo[0] = '<';
                    cadenaSimbolo[1] = FIN_CAD;
                    *simbolo = MENOR;
                    consumirChar(restante);
                }
                break;

            case '>':
                if (restante[1] == '=')
                {
                    cadenaSimbolo[0] = '>';
                    cadenaSimbolo[1] = '=';
                    cadenaSimbolo[2] = FIN_CAD;
                    *simbolo = MAYORIGUAL;
                    consumirChar(restante);
                    consumirChar(restante);
                }
                else
                {
                    cadenaSimbolo[0] = '>';
                    cadenaSimbolo[1] = FIN_CAD;
                    *simbolo = MAYOR;
                    consumirChar(restante);
                }
                break;

            case '+':
                cadenaSimbolo[0] = '+';
                cadenaSimbolo[1] = FIN_CAD;
                *simbolo = MAS;
                consumirChar(restante);
                break;

            case '-':
                cadenaSimbolo[0] = '-';
                cadenaSimbolo[1] = FIN_CAD;
                *simbolo = MENOS;
                consumirChar(restante);
                break;

            case '*':
                cadenaSimbolo[0] = '*';
                cadenaSimbolo[1] = FIN_CAD;
                *simbolo = MULTIPLICACION;
                consumirChar(restante);
                break;

            case '/':
                cadenaSimbolo[0] = '/';
                cadenaSimbolo[1] = FIN_CAD;
                *simbolo = DIVISION;
                consumirChar(restante);
                break;

            case '.':
                cadenaSimbolo[0] = '.';
                cadenaSimbolo[1] = FIN_CAD;
                *simbolo = PUNTO;
                consumirChar(restante);
                break;

            case ',':
                cadenaSimbolo[0] = ',';
                cadenaSimbolo[1] = FIN_CAD;
                *simbolo = COMA;
                consumirChar(restante);
                break;

            case ';':
                cadenaSimbolo[0] = ';';
                cadenaSimbolo[1] = FIN_CAD;
                *simbolo = PUNTOYCOMA;
                consumirChar(restante);
                break;

            case '(':
                cadenaSimbolo[0] = '(';
                cadenaSimbolo[1] = FIN_CAD;
                *simbolo = ABREPARENTESIS;
                consumirChar(restante);
                break;

            case ')':
                cadenaSimbolo[0] = ')';
                cadenaSimbolo[1] = FIN_CAD;
                *simbolo = CIERRAPARENTESIS;
                consumirChar(restante);
                break;

            default:
                cadenaSimbolo[0] = restante[0];
                cadenaSimbolo[1] = FIN_CAD;
                *simbolo = NULO;
                consumirChar(restante);
            }
        }
    }
}
/*
Función que recibe un simbolo del tipo enumerativo simbolo_t y lo traduce a la cadena que le corresponde
para poder visualizarlo por consola de forma más específica
*/
void imprimirSimbolo(simbolo_t simbolo, cadena_t cadenaSimbolo)
{
    printf("\t\t\"%s\" -> ", cadenaSimbolo);

    switch (simbolo)
    {
    case CONST:
        printf("CONST\n");
        break;

    case VAR:
        printf("VAR\n");
        break;

    case CALL:
        printf("CALL\n");
        break;

    case PROCEDURE:
        printf("PROCEDURE\n");
        break;

    case BEGIN:
        printf("BEGIN\n");
        break;

    case END:
        printf("END\n");
        break;

    case IF:
        printf("IF\n");
        break;

    case THEN:
        printf("THEN\n");
        break;

    case WHILE:
        printf("WHILE\n");
        break;

    case DO:
        printf("DO\n");
        break;

    case READLN:
        printf("READLN\n");
        break;

    case WRITE:
        printf("WRITE\n");
        break;

    case WRITELN:
        printf("WRITELN\n");
        break;

    case ODD:
        printf("ODD\n");
        break;

    case IDENT:
        printf("IDENT\n");
        break;

    case NUMERO:
        printf("NUMERO\n");
        break;

    case CADENA:
        printf("CADENA\n");
        break;

    case FINARCH:
        printf("FINARCH\n");
        break;

    case ASIGNACION:
        printf("ASIGNACION\n");
        break;

    case IGUAL:
        printf("IGUAL\n");
        break;

    case DISTINTO:
        printf("DISTINTO\n");
        break;

    case MENOR:
        printf("MENOR\n");
        break;

    case MENORIGUAL:
        printf("MENORIGUAL\n");
        break;

    case MAYOR:
        printf("MAYOR\n");
        break;

    case MAYORIGUAL:
        printf("MAYORIGUAL\n");
        break;

    case MAS:
        printf("MAS\n");
        break;

    case MENOS:
        printf("MENOS\n");
        break;

    case MULTIPLICACION:
        printf("MULTIPLICACION\n");
        break;

    case DIVISION:
        printf("DIVISION\n");
        break;

    case PUNTO:
        printf("PUNTO\n");
        break;

    case COMA:
        printf("COMA\n");
        break;

    case PUNTOYCOMA:
        printf("PUNTOYCOMA\n");
        break;

    case ABREPARENTESIS:
        printf("ABREPARENTESIS\n");
        break;

    case CIERRAPARENTESIS:
        printf("CIERRAPARENTESIS\n");
        break;

    case SQR:
        printf("SQR\n");
        break;

    case NULO:
        printf("NULO\n");
        break;
    }
}
//forma vieja
/*int busqueda(tabla_t tablaSimb, int tope, int inicio, cadena_t nombreSimb)
{
    int i;
    char nombreSimb2[50];
   // printf("retrocediendo desde: %d hasta: %d busca: %s\n", tope, inicio, nombreSimb);
    for (i = tope; i >= inicio; i--)
    {
       // strcpy(nombreSimb2,nombreSimb);
       // printf("%s\n",tablaSimb[i].nombre);
       // strupr(nombreSimb2);
       // printf("sin may: %s,con may:%s\n",nombreSimb,nombreSimb2);
        if ((strcmp(nombreSimb, tablaSimb[i].nombre) == 0)){
            break;
        }

      //  if (strcmp(nombreSimb2, tablaSimb[i].nombre) == 0)
      //  {
       //     break;
       // }
    }

    //printf("simbolo min: %s, Lista a comparar: %s\n",nombreSimb,tablaSimb[i].nombre);
    //printf("simbolo may: %s, Lista a comparar: %s\n",nombreSimb2,tablaSimb[i].nombre);

    if (i >= 0 && ((strcmp(strupr(nombreSimb), strupr(tablaSimb[i].nombre)) == 0||(strcmp(strupr(nombreSimb2), strupr(tablaSimb[i].nombre)) == 0)))){
    //printf("son iguales\n");
      // printf("Nombre del simbolo %s, Nombre de tabla simb (con el que se compara) %s \n",nombreSimb,tablaSimb[i].nombre);
        return i;
    }
    else if (i >= 0 && ((strcmp(strupr(nombreSimb), strupr(tablaSimb[i].nombre)) == 0||(strcmp(strupr(nombreSimb2), strupr(tablaSimb[i].nombre)) == 0)))){
    //printf("son iguales\n");
        //printf("Nombre del simbolo %s, Nombre de tabla simb (con el que se compara) %s \n",nombreSimb,tablaSimb[i].nombre);
        return i;
    } else
    {
        return -1;
    }
} */

//nueva forma
int busqueda(tabla_t tablaSimb, int tope, int inicio, cadena_t nombreSimb)
{
    int i;
    // printf("retrocediendo desde: %d hasta: %d busca: %s\n", tope, inicio, nombreSimb);
    for (i = tope; i >= inicio; i--)
    {
        if (strcmp(strupr(nombreSimb), strupr(tablaSimb[i].nombre)) == 0)
        {
            break;
        }
    }
    if (i >= 0 && strcmp(strupr(nombreSimb), strupr(tablaSimb[i].nombre)) == 0)
    {
        return i;
    }
    else
    {
        return -1;
    }
}
