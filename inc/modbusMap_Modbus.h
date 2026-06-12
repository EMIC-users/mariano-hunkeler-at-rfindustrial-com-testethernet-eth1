#ifndef MODBUSMAP_Modbus_H_
#define MODBUSMAP_Modbus_H_

#include <stdint.h>

/* Tipos / constantes del binding (los valores del artefacto son estos nombres) */
#define MB_INT16  0
#define MB_UINT16 1
#define MB_INT32  2
#define MB_UINT32 3
#define MB_FLOAT  4
#define MB_CMD    5
#define MB_ABCD   0
#define MB_CDAB   1
#define MB_R      0
#define MB_RW     1

typedef struct {
    uint16_t addr;                  /* primer registro del binding             */
    uint8_t  nRegs;                 /* 1 (16 bits / CMD) o 2 (32 bits)         */
    uint8_t  type;                  /* MB_*                                    */
    uint8_t  wordOrder;             /* MB_ABCD / MB_CDAB (solo 32 bits)        */
    uint8_t  access;                /* MB_R / MB_RW                            */
    void    *ptr;                   /* variable enlazada (0 en CMD)            */
    void   (*event)(uint16_t);      /* evento post-transaccion (0 si no hay)   */
} mbBinding_t;

/* Variables de la Data tab referenciadas por el mapa (definidas en userFncFile.c) */
extern int16_t miVar;
extern float Temp;
extern int32_t counr;
extern float Temp;

/* Eventos de comando (los implementa el integrador; firma del contrato) */
extern void ModbusTCP_Modbus_onMotorStart1(uint16_t value);

#define MB_MAP_SIZE 20

static const mbBinding_t mbBindings_Modbus[] = {
    { 0, 1, MB_CMD, MB_ABCD, MB_RW, (void*)0, (void (*)(uint16_t))ModbusTCP_Modbus_onMotorStart1 },
    { 1, 1, MB_INT16, MB_ABCD, MB_RW, (void*)&miVar, (void (*)(uint16_t))0 },
    { 2, 2, MB_FLOAT, MB_CDAB, MB_RW, (void*)&Temp, (void (*)(uint16_t))0 },
    { 4, 2, MB_INT32, MB_ABCD, MB_RW, (void*)&counr, (void (*)(uint16_t))0 },
    { 6, 2, MB_FLOAT, MB_ABCD, MB_R, (void*)&Temp, (void (*)(uint16_t))0 },
};
#define MB_NBINDINGS (sizeof mbBindings_Modbus / sizeof mbBindings_Modbus[0])

#endif
