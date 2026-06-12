
/*==================[inclusions]=============================================*/
#include <xc.h>
#include <string.h>
#include "inc/ModbusTCP_Modbus.h"
#include "inc/enc28j60.h"
#include "inc/modbusMap_Modbus.h"   /* mapa de bindings generado por el editor */

/* Validación cruzada modo (config bloqueante de instancia) <-> mapa (programa) */
#error "ModbusTCP Modbus: la instancia es mode=registers pero el programa define un Mapa Modbus. Quita el mapa, o instancia el modulo con mode=map."

/*==================[macros]=================================================*/
#define MB_NREGS 20
#define MB_PORT  502
#define TCP_ISN  0x1A2B3C4DUL

/*==================[internal data]==========================================*/
static const uint8_t my_mac[6] = { 0x00, 0x04, 0xA3, 0x11, 0x22, 0x33 };
static const uint8_t my_ip[4]  = { 192, 168, 0, 30 };

static uint8_t  rxbuf[600];

/*==================[internal functions]=====================================*/
// suma de a 16 bits big-endian, sin complementar (para encadenar)
static uint32_t sum16(const uint8_t *p, uint16_t n, uint32_t s)
{
    while (n > 1) {
        s += ((uint16_t)p[0] << 8) | p[1];
        p += 2;
        n -= 2;
    }
    if (n)
        s += (uint16_t)p[0] << 8;
    return s;
}

static uint16_t fin16(uint32_t s)
{
    while (s >> 16)
        s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t)~s;
}

// ¿ARP request preguntando por my_ip?
static int is_arp_for_me(const uint8_t *f, uint16_t n)
{
    return n >= 42 &&
           f[12] == 0x08 && f[13] == 0x06 &&     // ethertype ARP
           f[20] == 0x00 && f[21] == 0x01 &&     // oper: request
           memcmp(&f[38], my_ip, 4) == 0;        // TPA = mi IP
}

// Convierte el request (in place) en su reply y lo manda
static void arp_reply(uint8_t *f)
{
    memcpy(&f[0], &f[6], 6);        // dst eth = quien preguntó
    memcpy(&f[6], my_mac, 6);
    f[21] = 0x02;                   // oper: reply
    memcpy(&f[32], &f[22], 10);     // THA+TPA = SHA+SPA del request
    memcpy(&f[22], my_mac, 6);
    memcpy(&f[28], my_ip, 4);
    enc28j60_send(f, 42);
}

// ¿ICMP echo request a my_ip? (IPv4 sin opciones, frame completo en buf)
static int is_icmp_echo_for_me(const uint8_t *f, uint16_t n)
{
    uint16_t ip_len;

    if (n < 42 ||
        memcmp(&f[0], my_mac, 6) != 0 ||
        f[12] != 0x08 || f[13] != 0x00 ||       // ethertype IPv4
        f[14] != 0x45 ||                        // versión 4, IHL 20
        f[23] != 1 ||                           // protocolo ICMP
        memcmp(&f[30], my_ip, 4) != 0 ||
        f[34] != 8)                             // echo request
        return 0;
    ip_len = ((uint16_t)f[16] << 8) | f[17];
    return ip_len >= 28 && 14 + ip_len <= n;    // no truncado
}

// Convierte el echo request (in place) en echo reply y lo manda
static void icmp_reply(uint8_t *f)
{
    uint16_t ip_len = ((uint16_t)f[16] << 8) | f[17];
    uint16_t c;

    memcpy(&f[0], &f[6], 6);
    memcpy(&f[6], my_mac, 6);

    memcpy(&f[30], &f[26], 4);      // IP destino = quien preguntó
    memcpy(&f[26], my_ip, 4);
    f[22] = 64;                     // TTL
    f[24] = 0; f[25] = 0;
    c = fin16(sum16(&f[14], 20, 0));
    f[24] = c >> 8; f[25] = c & 0xFF;

    f[34] = 0;                      // echo reply
    f[36] = 0; f[37] = 0;
    c = fin16(sum16(&f[34], ip_len - 20, 0));
    f[36] = c >> 8; f[37] = c & 0xFF;

    enc28j60_send(f, 14 + ip_len);
}

/*==================[mapa de bindings]=======================================*/
// Modo MAPA: cada registro Modbus se sirve desde las variables vivas del
// integrador via la tabla const mbBindings (generada por el editor). No hay
// copia ni espejo: serializa/deserializa directo. Reglas del contrato:
// - Lectura de registro no bindeado -> 0; CMD lee 0 (v1, no almacena).
// - Escritura sobre no bindeado o binding R -> excepcion 0x02.
// - Escritura PARCIAL de un binding multi-registro -> excepcion 0x03 sin
//   escribir nada (validacion en pasada previa).
// - Eventos POST-transaccion: primero se escriben TODAS las variables,
//   despues se disparan los eventos (una vez por binding tocado), con el
//   primer word escrito del binding como parametro.

// Binding que CONTIENE al registro reg (lineal: el mapa es chico y const)
static const mbBinding_t *mb_find(uint16_t reg)
{
    uint16_t i;
    for (i = 0; i < MB_NBINDINGS; i++) {
        if (reg >= mbBindings_Modbus[i].addr &&
            reg <  mbBindings_Modbus[i].addr + mbBindings_Modbus[i].nRegs)
            return &mbBindings_Modbus[i];
    }
    return 0;
}

// Word de 16 bits que expone el registro reg (serializacion por tipo + word order)
static uint16_t mb_read_word(uint16_t reg)
{
    const mbBinding_t *b = mb_find(reg);
    uint32_t v32;

    if (!b)
        return 0;                               // no bindeado -> 0
    switch (b->type) {
    case MB_INT16:
    case MB_UINT16:
        return *(const uint16_t *)b->ptr;       // patron de bits (two's complement ok)
    case MB_CMD:
        return 0;                               // v1: comando puro lee 0
    default:                                    // 32 bits (int32/uint32/float)
        memcpy(&v32, b->ptr, 4);
        if ((reg - b->addr) == 0)
            return (b->wordOrder == MB_ABCD) ? (uint16_t)(v32 >> 16) : (uint16_t)v32;
        else
            return (b->wordOrder == MB_ABCD) ? (uint16_t)v32 : (uint16_t)(v32 >> 16);
    }
}

// Pasada 1: valida la escritura [addr, addr+cnt). 0 = OK, sino codigo de excepcion.
static uint8_t mb_write_check(uint16_t addr, uint16_t cnt)
{
    uint16_t r;
    const mbBinding_t *b;

    for (r = addr; r < addr + cnt; r++) {
        b = mb_find(r);
        if (!b || b->access != MB_RW)
            return 0x02;                        // no bindeado o solo lectura
        if (b->nRegs == 2 &&
            (b->addr < addr || b->addr + 2 > addr + cnt))
            return 0x03;                        // multi-registro cubierto a medias
    }
    return 0;
}

// Pasada 2: escribe los valores (d = words big-endian del PDU, ya validado)
static void mb_write_apply(uint16_t addr, uint16_t cnt, const uint8_t *d)
{
    uint16_t r = addr, w0, w1;
    uint32_t v32;
    const mbBinding_t *b;

    while (r < addr + cnt) {
        b  = mb_find(r);
        w0 = ((uint16_t)d[2 * (r - addr)] << 8) | d[2 * (r - addr) + 1];
        if (b->type == MB_INT16 || b->type == MB_UINT16) {
            *(uint16_t *)b->ptr = w0;
            r++;
        } else if (b->type == MB_CMD) {
            r++;                                // no almacena (solo evento)
        } else {                                // 32 bits: arranca en b->addr (validado)
            w1  = ((uint16_t)d[2 * (r - addr) + 2] << 8) | d[2 * (r - addr) + 3];
            v32 = (b->wordOrder == MB_ABCD) ? (((uint32_t)w0 << 16) | w1)
                                            : (((uint32_t)w1 << 16) | w0);
            memcpy(b->ptr, &v32, 4);
            r += 2;
        }
    }
}

// Pasada 3: eventos post-transaccion, una vez por binding tocado, en orden
static void mb_write_events(uint16_t addr, uint16_t cnt, const uint8_t *d)
{
    uint16_t r = addr;
    const mbBinding_t *b;

    while (r < addr + cnt) {
        b = mb_find(r);
        if (b->event)
            b->event(((uint16_t)d[2 * (r - addr)] << 8) | d[2 * (r - addr) + 1]);
        r += b->nRegs;
    }
}

// Procesa el PDU Modbus in-place; devuelve longitud del PDU de respuesta
static uint16_t mb_pdu(uint8_t *p, uint16_t len)
{
    uint8_t fc = p[0], exc;
    uint16_t addr, cnt, k, w;

    if (len < 5) {
        p[0] = fc | 0x80;
        p[1] = 0x01;
        return 2;
    }
    addr = ((uint16_t)p[1] << 8) | p[2];
    cnt  = ((uint16_t)p[3] << 8) | p[4];

    switch (fc) {
    case 0x03:                  // read holding registers
        if (cnt == 0 || cnt > MB_MAP_SIZE || addr + cnt > MB_MAP_SIZE) {
            p[0] = fc | 0x80;
            p[1] = 0x02;        // illegal data address
            return 2;
        }
        p[1] = cnt * 2;
        for (k = 0; k < cnt; k++) {
            w = mb_read_word(addr + k);
            p[2 + 2 * k] = w >> 8;
            p[3 + 2 * k] = w & 0xFF;
        }
        return 2 + cnt * 2;

    case 0x06:                  // write single register (cnt = valor)
        if (addr >= MB_MAP_SIZE) {
            p[0] = fc | 0x80;
            p[1] = 0x02;
            return 2;
        }
        exc = mb_write_check(addr, 1);
        if (exc) {
            p[0] = fc | 0x80;
            p[1] = exc;
            return 2;
        }
        mb_write_apply(addr, 1, &p[3]);
        mb_write_events(addr, 1, &p[3]);
        return 5;               // la respuesta es eco del request

    case 0x10:                  // write multiple registers
        if (cnt == 0 || addr + cnt > MB_MAP_SIZE ||
            len < 6 || p[5] != cnt * 2 || len < (uint16_t)(6 + p[5])) {
            p[0] = fc | 0x80;
            p[1] = 0x02;
            return 2;
        }
        exc = mb_write_check(addr, cnt);
        if (exc) {
            p[0] = fc | 0x80;
            p[1] = exc;
            return 2;
        }
        mb_write_apply(addr, cnt, &p[6]);
        mb_write_events(addr, cnt, &p[6]);
        return 5;               // respuesta: fc + addr + cnt

    default:
        p[0] = fc | 0x80;
        p[1] = 0x01;            // illegal function
        return 2;
    }
}

// TCP mínimo: maneja SYN/FIN/datos al puerto 502; responde in-place.
// Devuelve longitud del frame a transmitir (0 = nada).
static uint16_t tcp_handle(uint8_t *f, uint16_t n)
{
    uint16_t ip_len, hl, dlen, resp = 0, c;
    uint32_t seq, ack, sq2, ak2, s;
    uint8_t flags, rflags;

    if (n < 54 ||
        memcmp(&f[0], my_mac, 6) != 0 ||
        f[12] != 0x08 || f[13] != 0x00 ||   // IPv4
        f[14] != 0x45 ||                    // IHL 20, sin opciones IP
        f[23] != 6 ||                       // TCP
        memcmp(&f[30], my_ip, 4) != 0)
        return 0;

    ip_len = ((uint16_t)f[16] << 8) | f[17];
    if (ip_len < 40 || 14 + ip_len > n)
        return 0;
    if ((((uint16_t)f[36] << 8) | f[37]) != MB_PORT)
        return 0;

    hl    = (uint16_t)(f[46] >> 4) * 4;
    dlen  = ip_len - 20 - hl;
    flags = f[47];
    seq = ((uint32_t)f[38] << 24) | ((uint32_t)f[39] << 16) |
          ((uint32_t)f[40] << 8)  | f[41];
    ack = ((uint32_t)f[42] << 24) | ((uint32_t)f[43] << 16) |
          ((uint32_t)f[44] << 8)  | f[45];

    if (flags & 0x04)                   // RST
        return 0;

    if ((flags & 0x13) == 0x02) {       // SYN: contestar SYN|ACK
        rflags = 0x12;
        sq2 = TCP_ISN;
        ak2 = seq + 1;
    } else if (flags & 0x01) {          // FIN: cerrar con FIN|ACK
        rflags = 0x11;
        sq2 = ack;
        ak2 = seq + dlen + 1;
    } else if (dlen > 0) {              // datos: procesar Modbus
        uint8_t *mb = &f[34 + hl];
        uint16_t pdulen;

        if (dlen < 8)                   // MBAP (7) + FC mínimo
            return 0;
        pdulen = mb_pdu(&mb[7], dlen - 7);
        mb[4] = (pdulen + 1) >> 8;      // MBAP length = unit id + PDU
        mb[5] = (pdulen + 1) & 0xFF;
        resp = 7 + pdulen;
        if (hl != 20)                   // normalizar a header TCP de 20
            memmove(&f[54], &f[34 + hl], resp);
        rflags = 0x18;                  // PSH|ACK
        sq2 = ack;
        ak2 = seq + dlen;
    } else {
        return 0;                       // ACK puro: nada que hacer
    }

    // Ethernet: invertir direcciones
    memcpy(&f[0], &f[6], 6);
    memcpy(&f[6], my_mac, 6);

    // IP: invertir, largo nuevo, TTL, checksum
    memcpy(&f[30], &f[26], 4);
    memcpy(&f[26], my_ip, 4);
    ip_len = 20 + 20 + resp;
    f[16] = ip_len >> 8;  f[17] = ip_len & 0xFF;
    f[22] = 64;
    f[24] = 0; f[25] = 0;
    c = fin16(sum16(&f[14], 20, 0));
    f[24] = c >> 8; f[25] = c & 0xFF;

    // TCP: puertos invertidos, seq/ack, header 20, sin opciones
    f[36] = f[34]; f[37] = f[35];       // dst = puerto origen del request
    f[34] = MB_PORT >> 8; f[35] = MB_PORT & 0xFF;
    f[38] = sq2 >> 24; f[39] = sq2 >> 16; f[40] = sq2 >> 8; f[41] = sq2;
    f[42] = ak2 >> 24; f[43] = ak2 >> 16; f[44] = ak2 >> 8; f[45] = ak2;
    f[46] = 0x50;
    f[47] = rflags;
    f[48] = 600 >> 8; f[49] = 600 & 0xFF;   // ventana
    f[50] = 0; f[51] = 0;
    f[52] = 0; f[53] = 0;

    // Checksum TCP: pseudo-header + segmento
    s = sum16(&f[26], 8, 0);            // IPs origen + destino
    s += 6;                             // protocolo
    s += 20 + resp;                     // longitud TCP
    s = sum16(&f[34], 20 + resp, s);
    c = fin16(s);
    f[50] = c >> 8; f[51] = c & 0xFF;

    return 34 + 20 + resp;
}

/*==================[external functions]=====================================*/
void ModbusTCP_Modbus_init(void)
{

    enc28j60_init(my_mac);
}

void ModbusTCP_Modbus_poll(void)
{
    uint16_t n, txn;

    n = enc28j60_recv(rxbuf, sizeof rxbuf);
    if (n == 0)
        return;

    if (is_arp_for_me(rxbuf, n)) {
        arp_reply(rxbuf);
    } else if (is_icmp_echo_for_me(rxbuf, n)) {
        icmp_reply(rxbuf);
    } else {
        txn = tcp_handle(rxbuf, n);
        if (txn > 0)
            enc28j60_send(rxbuf, txn);
    }
}

// setReg/getReg operan sobre holding[] — SOLO existen en modo legacy. Con mapa de
// bindings el integrador lee/escribe sus variables directamente (usar setReg con
// mapa da error de link a propósito: no tiene semántica sobre los bindings).
/*==================[end of file]============================================*/

