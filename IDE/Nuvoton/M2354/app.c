/* app.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* wolfCrypt test and benchmark on the NuMaker-M2354.
 *
 * Brings the clocks and the console up, registers the crypto callback device,
 * then runs the algorithm test followed by the benchmark. Output goes to
 * UART0, which the on board Nu-Link2-Me presents as a virtual COM port at
 * 115200 baud.
 */

/* NuMicro.h first: M2354.h defines TRUE and FALSE unconditionally and would
 * redefine the ones types.h puts up behind an #ifndef. */
#include "NuMicro.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/port/nuvoton/nuvoton_cryptocb.h>
#include <wolfcrypt/test/test.h>
#include <wolfcrypt/benchmark/benchmark.h>

#include <stdio.h>

/* Free running millisecond counter, driven by SysTick. */
static volatile word32 msTicks = 0;

void SysTick_Handler(void);
void CRPT_IRQHandler(void);

void SysTick_Handler(void)
{
    msTicks++;
}

/* The BSP public key drivers block on a flag that only this interrupt sets
 * (see ECC_DriverISR in Library/StdDriver/src/crypto.c). Without this handler
 * every ECC and RSA call would spin until its timeout and fail. */
void CRPT_IRQHandler(void)
{
    ECC_DriverISR(CRPT);
}

/* WOLFSSL_USER_CURRTIME: seconds, used by the benchmark to work out rates. */
double current_time(int reset)
{
    if (reset) {
        msTicks = 0;
    }

    return (double)msTicks / 1000.0;
}

/* USER_TICKS: coarse seconds counter. */
word32 LowResTimer(void)
{
    return msTicks / 1000;
}

/* Route printf to UART0. */
int _write(int fd, const char* buf, int len)
{
    int i;

    (void)fd;

    for (i = 0; i < len; i++) {
        if (buf[i] == '\n') {
            UART_WRITE(UART0, '\r');
        }
        UART_WRITE(UART0, (uint8_t)buf[i]);
    }

    return len;
}

/* The BSP startup calls these two by name. ProcessHardFault gets the stacked
 * register frame and returns the address to resume at; parking in a loop keeps
 * a fault visible under the debugger instead of silently restarting.
 * SH_Return belongs to the BSP's semihosting path, which is not used here. */
uint32_t ProcessHardFault(uint32_t lr, uint32_t msp, uint32_t psp);
int32_t SH_Return(int32_t n32In_R0, int32_t n32In_R1, int32_t* pn32Out_R0);

uint32_t ProcessHardFault(uint32_t lr, uint32_t msp, uint32_t psp)
{
    (void)lr;
    (void)msp;
    (void)psp;

    printf("\nhard fault\n");

    while (1) {
        /* Stop here so the fault state can be read out. */
    }
}

int32_t SH_Return(int32_t n32In_R0, int32_t n32In_R1, int32_t* pn32Out_R0)
{
    (void)n32In_R0;
    (void)n32In_R1;
    (void)pn32Out_R0;

    return 0;
}

static void SYS_Init(void)
{
    SYS_UnlockReg();

    /* 12 MHz crystal into the PLL, out at the part's 96 MHz ceiling. */
    CLK_EnableXtalRC(CLK_PWRCTL_HXTEN_Msk);
    CLK_WaitClockReady(CLK_STATUS_HXTSTB_Msk);
    CLK_SetCoreClock(FREQ_96MHZ);

    /* HIRC for UART0 so the console survives a PLL change. */
    CLK_EnableModuleClock(UART0_MODULE);
    CLK_SetModuleClock(UART0_MODULE, CLK_CLKSEL2_UART0SEL_HIRC,
        CLK_CLKDIV0_UART0(1));

    /* NuMaker-M2354 wires the Nu-Link2-Me virtual COM port to PB12/PB13. */
    SYS->GPB_MFPH &= ~(SYS_GPB_MFPH_PB12MFP_Msk | SYS_GPB_MFPH_PB13MFP_Msk);
    SYS->GPB_MFPH |= (SYS_GPB_MFPH_PB12MFP_UART0_RXD |
                      SYS_GPB_MFPH_PB13MFP_UART0_TXD);

    SystemCoreClockUpdate();

    SYS_LockReg();
}

int main(void)
{
    int ret;

    SYS_Init();
    UART_Open(UART0, 115200);

    /* One tick per millisecond for current_time() and LowResTimer(). */
    SysTick_Config(SystemCoreClock / 1000);

    /* The public key engines need this interrupt; see CRPT_IRQHandler. */
    NVIC_EnableIRQ(CRPT_IRQn);

    printf("\nwolfCrypt on NuMaker-M2354 (%u MHz)\n",
        (unsigned int)(SystemCoreClock / 1000000));
#ifdef WOLFSSL_NUVOTON_NSC
    printf("TrustZone: non-secure, hardware through NSC veneers\n");
#else
    printf("TrustZone: secure world, direct BSP calls\n");
#endif

    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("wolfCrypt_Init failed: %d\n", ret);
        return ret;
    }

    ret = wc_NuvotonCryptoCb_RegisterDevice(WOLFSSL_NUVOTON_DEVID);
    if (ret != 0) {
        printf("Nuvoton device registration failed: %d\n", ret);
        return ret;
    }
    printf("Nuvoton crypto callback device registered as devId %d\n",
        WOLFSSL_NUVOTON_DEVID);

    printf("\n--- wolfcrypt_test ---\n");
    ret = wolfcrypt_test(NULL);
    printf("wolfcrypt_test returned %d\n", ret);

    printf("\n--- benchmark ---\n");
    benchmark_test(NULL);

    wc_NuvotonCryptoCb_UnRegisterDevice(WOLFSSL_NUVOTON_DEVID);
    wolfCrypt_Cleanup();

    printf("\ndone\n");

    while (1) {
        /* Nothing left to do; leave the console output on screen. */
    }
}
