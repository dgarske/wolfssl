/* nuvoton_nsc.c
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

/* Non-secure callable entry points for the M2354 port.
 *
 * The CRPT accelerator, the TRNG and the Key Store are secure only in the
 * default SCU partition, and M2354.h has no KS_NS alias at all, so a
 * non-secure wolfCrypt cannot reach any of them directly. This file is the
 * secure half: one veneer per wc_nuvoton_hw_* call, each checking that the
 * buffers the non-secure side passed really belong to the non-secure world
 * before handing them to the driver.
 *
 * Build it into the secure image together with wolfcrypt/src/port/nuvoton/
 * nuvoton_hw.c, with -mcmse and -DWOLFSSL_NUVOTON_NSC_IMPL. That macro renames
 * the implementations to wc_nuvoton_hw_*_s (see nuvoton_hw.h) so the veneers
 * below can take the plain names, which is what the non-secure image links
 * against through the import library the linker emits.
 *
 * The non-secure side builds the same port sources with
 * -DWOLFSSL_NUVOTON_NSC, which leaves nuvoton_hw.c empty.
 */

#include "NuMicro.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif

#include "wolfcrypt/src/port/nuvoton/nuvoton_hw.h"

#include <arm_cmse.h>

#ifndef WOLFSSL_NUVOTON_NSC_IMPL
    #error "Build the secure side with -DWOLFSSL_NUVOTON_NSC_IMPL"
#endif

/* nuvoton_hw.h has just declared the implementations under their _s names.
 * Drop the macros so the veneers below define the plain names the non-secure
 * image links against, while still being able to call the _s ones. */
#undef wc_nuvoton_hw_init
#undef wc_nuvoton_hw_cleanup
#undef wc_nuvoton_hw_trng
#undef wc_nuvoton_hw_sha
#undef wc_nuvoton_hw_aes
#undef wc_nuvoton_hw_ecc_sign
#undef wc_nuvoton_hw_ecc_verify
#undef wc_nuvoton_hw_ecc_shared
#undef wc_nuvoton_hw_ecc_pubkey
#undef wc_nuvoton_hw_rsa
#undef wc_nuvoton_hw_ks_write
#undef wc_nuvoton_hw_ks_read
#undef wc_nuvoton_hw_ks_erase
#undef wc_nuvoton_hw_ks_revoke

#define NSC_ENTRY __attribute__((cmse_nonsecure_entry))

/* Refuse a buffer that is not entirely non-secure and readable, or writable
 * when the veneer is going to write to it. A non-secure caller must not be
 * able to talk the secure world into reading or overwriting secure memory. */
static int nsc_check(void* p, word32 sz, int write)
{
    int flags = CMSE_NONSECURE | CMSE_MPU_READ;

    if (p == NULL || sz == 0) {
        return 0;
    }
    if (write) {
        flags |= CMSE_MPU_READWRITE;
    }

    return (cmse_check_address_range(p, sz, flags) != NULL);
}

/* Same, for the NUL terminated hex strings the public key requests carry. The
 * length is not known up front, so the string is measured inside a bound and
 * then the whole span is checked in one go. */
static int nsc_check_str(char* s, word32 maxSz, word32* lenOut)
{
    word32 i;

    if (s == NULL) {
        return 0;
    }
    if (!nsc_check(s, 1, 0)) {
        return 0;
    }

    for (i = 0; i < maxSz; i++) {
        if (!nsc_check(s + i, 1, 0)) {
            return 0;
        }
        if (s[i] == '\0') {
            if (lenOut != NULL) {
                *lenOut = i + 1;
            }
            return 1;
        }
    }

    return 0;
}

NSC_ENTRY int wc_nuvoton_hw_init(void)
{
    return wc_nuvoton_hw_init_s();
}

NSC_ENTRY void wc_nuvoton_hw_cleanup(void)
{
    wc_nuvoton_hw_cleanup_s();
}

NSC_ENTRY int wc_nuvoton_hw_trng(byte* out, word32 sz)
{
    if (!nsc_check(out, sz, 1)) {
        return BAD_FUNC_ARG;
    }

    return wc_nuvoton_hw_trng_s(out, sz);
}

NSC_ENTRY int wc_nuvoton_hw_sha(wc_NuvotonShaReq* req)
{
    wc_NuvotonShaReq local;

    if (!nsc_check(req, (word32)sizeof(*req), 1)) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(&local, req, sizeof(local));

    if (!nsc_check((void*)local.in, local.inSz, 0) ||
        !nsc_check(local.digest, local.digestSz, 1)) {
        return BAD_FUNC_ARG;
    }

    return wc_nuvoton_hw_sha_s(&local);
}

NSC_ENTRY int wc_nuvoton_hw_aes(wc_NuvotonAesReq* req)
{
    wc_NuvotonAesReq local;

    /* Copy the request into secure memory first, so the non-secure side
     * cannot change a length or a pointer after it has been checked. */
    if (!nsc_check(req, (word32)sizeof(*req), 1)) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(&local, req, sizeof(local));

    if (!nsc_check((void*)local.in, local.sz, 0) ||
        !nsc_check(local.out, local.sz, 1) ||
        !nsc_check((void*)local.key, local.keySz, 0) ||
        !nsc_check(local.iv, local.iv != NULL ? WC_AES_BLOCK_SIZE : 0, 1) ||
        !nsc_check((void*)local.aad, local.aadSz, 0) ||
        !nsc_check(local.tag, local.tagSz, 1)) {
        return BAD_FUNC_ARG;
    }

    return wc_nuvoton_hw_aes_s(&local);
}

#ifdef WOLFSSL_NUVOTON_ECC
/* Longest string the ECC requests carry: P-521 is 132 hex characters. */
#define NSC_ECC_STR_MAX 160

static int nsc_ecc_strings_ok(wc_NuvotonEccReq* r)
{
    char*  in[4];
    char*  out[3];
    word32 i;

    in[0] = r->msg;
    in[1] = r->d;
    in[2] = r->k;
    in[3] = r->qx;

    for (i = 0; i < 4; i++) {
        if (in[i] != NULL && !nsc_check_str(in[i], NSC_ECC_STR_MAX, NULL)) {
            return 0;
        }
    }
    if (r->qy != NULL && !nsc_check_str(r->qy, NSC_ECC_STR_MAX, NULL)) {
        return 0;
    }

    /* The engine writes these, so they need write access for the full width
     * it will fill, not just up to the current NUL. */
    out[0] = r->r;
    out[1] = r->s;
    out[2] = r->out;

    for (i = 0; i < 3; i++) {
        if (out[i] != NULL && !nsc_check(out[i], NSC_ECC_STR_MAX, 1)) {
            return 0;
        }
    }

    return 1;
}

NSC_ENTRY int wc_nuvoton_hw_ecc_sign(wc_NuvotonEccReq* req)
{
    wc_NuvotonEccReq local;

    if (!nsc_check(req, (word32)sizeof(*req), 1)) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(&local, req, sizeof(local));

    if (!nsc_ecc_strings_ok(&local)) {
        return BAD_FUNC_ARG;
    }

    return wc_nuvoton_hw_ecc_sign_s(&local);
}

NSC_ENTRY int wc_nuvoton_hw_ecc_verify(wc_NuvotonEccReq* req)
{
    wc_NuvotonEccReq local;

    if (!nsc_check(req, (word32)sizeof(*req), 1)) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(&local, req, sizeof(local));

    if (!nsc_ecc_strings_ok(&local)) {
        return BAD_FUNC_ARG;
    }

    return wc_nuvoton_hw_ecc_verify_s(&local);
}

NSC_ENTRY int wc_nuvoton_hw_ecc_shared(wc_NuvotonEccReq* req)
{
    wc_NuvotonEccReq local;

    if (!nsc_check(req, (word32)sizeof(*req), 1)) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(&local, req, sizeof(local));

    if (!nsc_ecc_strings_ok(&local)) {
        return BAD_FUNC_ARG;
    }

    return wc_nuvoton_hw_ecc_shared_s(&local);
}

NSC_ENTRY int wc_nuvoton_hw_ecc_pubkey(wc_NuvotonEccReq* req)
{
    wc_NuvotonEccReq local;

    if (!nsc_check(req, (word32)sizeof(*req), 1)) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(&local, req, sizeof(local));

    if (!nsc_ecc_strings_ok(&local)) {
        return BAD_FUNC_ARG;
    }

    return wc_nuvoton_hw_ecc_pubkey_s(&local);
}
#endif /* WOLFSSL_NUVOTON_ECC */

#ifdef WOLFSSL_NUVOTON_RSA
NSC_ENTRY int wc_nuvoton_hw_rsa(wc_NuvotonRsaReq* req)
{
    wc_NuvotonRsaReq local;
    /* 4096 bits is 1024 hex characters plus the NUL. */
    const word32     strMax = 1088;

    if (!nsc_check(req, (word32)sizeof(*req), 1)) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(&local, req, sizeof(local));

    if (!nsc_check_str(local.in, strMax, NULL) ||
        !nsc_check_str(local.n, strMax, NULL) ||
        !nsc_check_str(local.e, strMax, NULL)) {
        return BAD_FUNC_ARG;
    }
    if (local.p != NULL && !nsc_check_str(local.p, strMax, NULL)) {
        return BAD_FUNC_ARG;
    }
    if (local.q != NULL && !nsc_check_str(local.q, strMax, NULL)) {
        return BAD_FUNC_ARG;
    }
    if (local.outSz > strMax || !nsc_check(local.out, local.outSz, 1)) {
        return BAD_FUNC_ARG;
    }

    return wc_nuvoton_hw_rsa_s(&local);
}
#endif /* WOLFSSL_NUVOTON_RSA */

#ifdef WOLFSSL_NUVOTON_KS
NSC_ENTRY int wc_nuvoton_hw_ks_write(wc_NuvotonKsWriteReq* req)
{
    wc_NuvotonKsWriteReq local;

    if (!nsc_check(req, (word32)sizeof(*req), 1)) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(&local, req, sizeof(local));

    if (!nsc_check((void*)local.key, local.keySz, 0)) {
        return BAD_FUNC_ARG;
    }

    return wc_nuvoton_hw_ks_write_s(&local);
}

NSC_ENTRY int wc_nuvoton_hw_ks_read(int keyMem, int keySlot, byte* out,
    word32 outSz)
{
    if (!nsc_check(out, outSz, 1)) {
        return BAD_FUNC_ARG;
    }

    return wc_nuvoton_hw_ks_read_s(keyMem, keySlot, out, outSz);
}

NSC_ENTRY int wc_nuvoton_hw_ks_erase(int keyMem, int keySlot)
{
    return wc_nuvoton_hw_ks_erase_s(keyMem, keySlot);
}

NSC_ENTRY int wc_nuvoton_hw_ks_revoke(int keyMem, int keySlot)
{
    return wc_nuvoton_hw_ks_revoke_s(keyMem, keySlot);
}
#endif /* WOLFSSL_NUVOTON_KS */
