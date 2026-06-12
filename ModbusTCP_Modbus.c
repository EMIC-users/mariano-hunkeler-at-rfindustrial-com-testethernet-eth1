
/*==================[inclusions]=============================================*/
#include <xc.h>
#include <string.h>
#include "inc/ModbusTCP_Modbus.h"
#include "inc/enc28j60.h"

/*==================[macros]=================================================*/
#define MB_NREGS 20
#define MB_PORT  502
#define TCP_ISN  0x1A2B3C4DUL

/*==================[internal data]==========================================*/
static const uint8_t my_mac[6] = { 0x00, 0x04, 0xA3, 0x11, 0x22, 0x33 };
static const uint8_t my_ip[4]  = { 192, 168, 0, 30 };

static uint8_t  rxbuf[600];
static uint16_t holding[MB_NREGS];

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

// Procesa el PDU Modbus in-place; devuelve longitud del PDU de respuesta
static uint16_t mb_pdu(uint8_t *p, uint16_t len)
{
    uint8_t fc = p[0];
    uint16_t addr, cnt, k;

    if (len < 5) {
        p[0] = fc | 0x80;
        p[1] = 0x01;
        return 2;
    }
    addr = ((uint16_t)p[1] << 8) | p[2];
    cnt  = ((uint16_t)p[3] << 8) | p[4];

    switch (fc) {
    case 0x03:                  // read holding registers
        if (cnt == 0 || cnt > MB_NREGS || addr + cnt > MB_NREGS) {
            p[0] = fc | 0x80;
            p[1] = 0x02;        // illegal data address
            return 2;
        }
        p[1] = cnt * 2;
        for (k = 0; k < cnt; k++) {
            p[2 + 2 * k] = holding[addr + k] >> 8;
            p[3 + 2 * k] = holding[addr + k] & 0xFF;
        }
        return 2 + cnt * 2;

    case 0x06:                  // write single register (cnt = valor)
        if (addr >= MB_NREGS) {
            p[0] = fc | 0x80;
            p[1] = 0x02;
            return 2;
        }
        holding[addr] = cnt;
        ModbusTCP_Modbus_onRegWritten(addr, cnt);
        return 5;               // la respuesta es eco del request

    case 0x10:                  // write multiple registers
        if (cnt == 0 || addr + cnt > MB_NREGS ||
            len < 6 || p[5] != cnt * 2 || len < (uint16_t)(6 + p[5])) {
            p[0] = fc | 0x80;
            p[1] = 0x02;
            return 2;
        }
        for (k = 0; k < cnt; k++) {
            holding[addr + k] = ((uint16_t)p[6 + 2 * k] << 8) | p[7 + 2 * k];
            ModbusTCP_Modbus_onRegWritten(addr + k, holding[addr + k]);
        }
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
    uint16_t k;

    for (k = 0; k < MB_NREGS; k++)
        holding[k] = 0x1000 + k;    // patrón reconocible para validar

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

void ModbusTCP_Modbus_setReg(uint8_t addr, uint16_t value)
{
    if (addr < MB_NREGS)
        holding[addr] = value;
}

/*==================[end of file]============================================*/

