/*******************************************************************************
* Copyright 2019-2020 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

/*!
 *
 *  \file
 *
 *  \brief RSA multi buffer encryption and decryption algorithms usage example.
 *
 *  This example demonstrates message encryption and decryption according to
 *  RSA algorithm with 1024-bit RSA modulus.
 *  It shows a possible way to process a queue of encryption requests on one
 *  host and decryption requests on another.
 *
 *  The RSA encryption and decryption algorithms are implemented according to the PKCS#1 v2.1: RSA Cryptography Standard (June 2002),
 *  available at:
 *
 *  https://tools.ietf.org/html/rfc3447.
 *
 */

#include <cstring>
#include <cstdlib>
#include <time.h>
#include <chrono>

#include <stdio.h>

#include <gmp.h>

#include <assert.h> 
#include "ippcp.h"
#include "examples_common.h"
#include "bignum.h"
#include "rsa_mb_data.h"
#include "requests.h"
#include "immintrin.h"
#define ENABLE_GMP 1
using namespace std;
using namespace chrono;

/*! Check compatibility of encryption requests */
static bool CheckEncRequestsCompatibility(Request *request1, Request *request2)
{
    bool compatibilityStatus = (request1->GetValueE() == request2->GetValueE()) && (request1->GetBitSizeN() == request2->GetBitSizeN());

    return compatibilityStatus;
}

/*! Check compatibility of decryption requests */
static bool CheckDecRequestsCompatibility(Request *request1, Request *request2)
{
    bool compatibilityStatus = request1->GetBitSizeN() == request2->GetBitSizeN();

    return compatibilityStatus;
}

/*! Check matching of the private key types */
static bool CheckPrivateKeyCompatibility(IppsRSAPrivateKeyState *pPrivKey1, IppsRSAPrivateKeyState *pPrivKey2)
{
    /* Inside ippsRSA_GetPrivateKeyType1 and ippsRSA_GetPrivateKeyType2 there is a check of the pPrivKey type */
    bool isMatched = (ippsRSA_GetPrivateKeyType1(NULL, NULL, pPrivKey1) == ippStsNoErr) &&
                     (ippsRSA_GetPrivateKeyType1(NULL, NULL, pPrivKey2) == ippStsNoErr);

    /* Check for belonging to the Type2 only if the type of both keys is not Type1 */
    if (!isMatched)
        isMatched = (ippsRSA_GetPrivateKeyType2(NULL, NULL, NULL, NULL, NULL, pPrivKey1) == ippStsNoErr) &&
                    (ippsRSA_GetPrivateKeyType2(NULL, NULL, NULL, NULL, NULL, pPrivKey2) == ippStsNoErr);

    return isMatched;
}
//#define limbs 32

typedef unsigned int uint32_t;

typedef struct
{
    mpz_t* bigint;
    int num;
    bool ismalloc = 0;

}fate_bignum;


void vec2gmp(vector<Ipp32u> &vec, mpz_t g)
{
    uint32_t num = vec.size();
    uint32_t bit = vec.size() * 32;
    uint32_t *h_d = (uint32_t *)malloc(sizeof(uint32_t) * num);
    //printf("vec.size = %d \n", vec.size());
    for (int i = 0; i < vec.size(); i++)
    {
        h_d[i] = vec[i];
        //printf("[%d] %d \n", i, vec[i]);
    }
    mpz_init(g);
    mpz_setbit(g, bit);
    mpz_import(g, num, -1, sizeof(uint32_t), 0, 0, h_d);
}

void num2gmp(BigNumber &n, mpz_t g)
{
    vector<Ipp32u> tmp;
    n.num2vec(tmp);

    assert(tmp.size() == 32);

    uint32_t num = tmp.size();
    
    uint32_t bit = tmp.size() * (sizeof(int) * 8);
    uint32_t *h_d = (uint32_t *)malloc(sizeof(uint32_t) * num);
    //printf("vec.size = %d \n", vec.size());
    for (int i = 0; i < tmp.size(); i++)
    {
        h_d[i] = tmp[i];
        //printf("[%d] %d \n", i, tmp[i]);
    }
    //mpz_init(g);
    mpz_setbit(g, bit);
    mpz_import(g, num, -1, sizeof(uint32_t), 0, 0, h_d);
}

BigNumber gmp2num(mpz_t g)
{
    assert(g->_mp_size == 16);

    Ipp32u* ipp = (Ipp32u*)malloc(sizeof(int) * 32);
    memcpy(ipp, (void*)g->_mp_d, sizeof(uint32_t) * 32);

    int* iter0 = (int*)g->_mp_d;

    //for (int i = 0; i < 32; i++)
    //{
    //    printf("%d\n", iter0[i]);
    //}
    //printf("XXXX\n");
    //gmp_printf("%Zd\n", g);

    //mpz_export(ipp, NULL, 1, sizeof(uint32_t), 0, 0, g);

    return BigNumber(ipp, 32);
}

void rsa(mpz_t res, mpz_t pln, mpz_t e, mpz_t n, bool out)
{
    //mpz_init(res);
    mpz_powm(res, pln, e, n);

    int *iter0 = (int *)pln->_mp_d;
    int *iter1 = (int *)e->_mp_d;
    int *iter2 = (int *)n->_mp_d;
    int *iter3 = (int *)res->_mp_d;

    if (out)
    {

        for (int i = 0; i < 4; i++)
        {
            printf("XXXXXXXXXXXXXres = %d pln = %d e = %d n =%d \n", iter3[i], iter0[i], iter1[i], iter2[i]);
        }
        printf("**********************\n");
    }
}

void g_printf(mpz_t g, vector<Ipp32u> &v)
{
    //printf("alloc = %d size = %d \n", g->_mp_alloc, g->_mp_size);
    int *iter = (int *)g->_mp_d;
    int gs = g->_mp_size * 2;
    int vs = v.size();
    if (gs != vs)
        printf("XXXXXXX size diffXXXXXXXX\n");

    for (int i = 0; i < gs; i++)
    {
        printf("%d %d\n", iter[i], v[i]);
    }
}

int g_Comp(mpz_t g, vector<Ipp32u> &v)
{
    //printf("alloc = %d size = %d \n", g->_mp_alloc, g->_mp_size);
    uint32_t *iter = (uint32_t *)g->_mp_d;
    int gs = g->_mp_size * 2;
    int vs = v.size();
    //printf("gs = %d vs = %d \n", gs, vs);
    if (gs != vs)
    {
        printf("XXXXXXX size diffXXXXXXXX\n");
        return -1;
    }

    for (int i = 0; i < gs; i++)
    {
        if (v[i] != iter[i])
        {
            printf("error ~~~\n", v[i], iter[i]);
            printf("%d %d\n", iter[i], v[i]);
            return -1;
        }
    }
    return 1;
}

int mpzComp(mpz_t g1, mpz_t g2)
{
    //printf("alloc = %d size = %d \n", g->_mp_alloc, g->_mp_size);
    uint32_t *iter1 = (uint32_t *)g1->_mp_d;
    uint32_t *iter2 = (uint32_t *)g2->_mp_d;
    int size1 = g1->_mp_size;
    int size2 = g2->_mp_size;

    //printf("gs = %d vs = %d \n", gs, vs);
    if (size1 != size2)
    {
        printf("XXXXXXX size diffXXXXXXXX\n");
        return -1;
    }

    for (int i = 0; i < size2; i++)
    {
        //printf("%d %d\n", iter1[i], iter2[i]);
        if (iter1[i] != iter2[i])
        {
            printf("error ~~~\n");
            // printf("%d %d\n", iter1[i], iter2[i]);
            return -1;
        }
    }
    return 1;
}

int numComp(BigNumber a, BigNumber b)
{
    vector<Ipp32u> v, u;
    a.num2vec(v);
    b.num2vec(u);
    if (v.size() != u.size())
    {
        return -1;
    }

    for (int i = 0; i < v.size(); i++)
    {

        printf("[%d]val = %d %d\n", i, v[i], u[i]);

        if (v[i] != u[i])
        {
            printf("error ~~~\n", v[i], u[i]);
            return -1;
        }
    }
    return 1;
}

BigNumber genrand()
{
    srand((unsigned int)clock());

    Ipp32u *ipp = (Ipp32u *)malloc(sizeof(int) * 32);
    for (int i = 0; i < 32; i++)
    {
        ipp[i] = rand();
    }

    return BigNumber(ipp, 32);
}

void genrand_gmp(mpz_t g)
{
    printf("size = %d \n", g->_mp_size);
    printf("alloc = %d \n", g->_mp_alloc);
    assert(g->_mp_alloc== 16);

    srand((unsigned int)clock());
    int* iter = (int*)g->_mp_d;
    for (int i = 0; i < 32; i++)
    {
        iter[i] = rand();
    }
    g->_mp_size = 16;

}


static BigNumber _E("0x010001");

static BigNumber _DD("0x6C874DB1FD6452F9316632FF35294FDF3251A31E807F8033609DCC9BE8302084E75A4DC3BEC614DF11A22CAA57816CC1C4"
                     "484934F5E48F0F5C694C3CFA2AAF07D08D17559128BC5ECD6F922D867B93A8477D756646619104C22135595BAF90B1D6540F96FE657BB1F"
                     "A8E452975099FFC74D7ACDB1932E4AC8C45E6F3C2107D06");
static BigNumber _N1("0x803592FEE464EF01A013527FA3EB96B1770DDEE9BA28A1DA5CF748E7224912B13F960F896212B1653E0CC0856D98CC46628681A1FBEBC0"
                     "58ACACCBA67DF2E8524AED315B08E52A05DF151B516141122667327FD4D5795E2A93B00676F9C01AE5B1F4CC2EED4769333D9531E6B35B5"
                     "360070C29E6CFCA03619C01ECB08538BC5F");
static BigNumber _D1("0x7AABC8141E8FFCA77F743D71677418E1805A43393B277985A781EBBD4B6EC375D8B349F657622F5E017ACE125C84E09F4FD206E2E859EF"
                     "D6689184E1AE8CE67FB9B56C3D42052FDACE4A2EB233EDA40A6E538DF53D19F2ADC886767F7157A1B2FCFF5CDCBF5EB4A822053AB2A4FB9"
                     "B1AAECB4EF408AEE537BD10922757957401");

#define CK_DE 1
int main1()
{
    /*CCCC**/
    const int num = 16;
    const int buf = 8;
    const int crypt = 10;

    if (num % buf != 0)
        return 0;

    Request *req[num];
    //Request** req = (Request**)malloc(sizeof(void*) * num);
    clock_t str = clock();
    int idx;
    for (int i = 0; i < num; i++)
    {
        idx = i % 8; //rand() % (crypt);
        //req[i] = new Request(plainTextArray[idx], _N1, _E, _D1);
        req[i] = new Request(genrand(), _N1, _E, _D1);
    }

    if (ENABLE_GMP)
        for (int i = 0; i < 2; i++)
        {

            BigNumber bnTmp1 = req[i]->GetDecipherText();
            BigNumber bnTmp2 = req[i]->GetPlainText();
            BigNumber bnTmp3 = req[i]->GetCipherText();
            vector<Ipp32u> tmp1;
            vector<Ipp32u> tmp2;
            vector<Ipp32u> tmp3;
            bnTmp1.num2vec(tmp1);
            bnTmp2.num2vec(tmp2);
            bnTmp3.num2vec(tmp3);
            printf("XXX%d \n", tmp1.size());
            //for (int i = 0; i < tmp1.size(); i++)
            for (int j = 0; j < 4; j++)
            {
                printf("cipher =  %d\n", tmp3[j]);
            }
            printf("===========================\n");
        }

    IppStatus status = ippStsNoErr;
    IppStatus statusesArray[buf];

    IppsRSAPublicKeyState *pPubKey[buf];
    IppsRSAPrivateKeyState *pPrivKey[buf];
    IppsBigNumState *mbPlainTextArray[buf];
    IppsBigNumState *mbCipherTextArray[buf];
    IppsBigNumState *mbDecipherTextArray[buf];

    int bitSizeN, bitSizeE, bitSizeD;
    int bufId = 0;
    // auto start = system_clock::now();

    if (ENABLE_GMP)
    {
        BigNumber _p = req[0]->GetPlainText();
        BigNumber _c = req[0]->GetCipherText();
        BigNumber _d = req[0]->GetDecipherText();
        vector<Ipp32u> _vp;
        vector<Ipp32u> _vc;
        vector<Ipp32u> _vd;
        _p.num2vec(_vp);
        _c.num2vec(_vc);
        _d.num2vec(_vd);
        for (int i = 0; i < 8; i++)
        {
            printf("11111111 p = %d c = %d d = %d\n", _vp[i], _vc[i], _vd[i]);
        }
    }
    /*========================================================= ENC =================================================*/

    for (int i = 0; i < num; i++)
    {
        //printf("%d ", i);
        bitSizeN = req[i]->GetBitSizeN();
        bitSizeE = _E.BitSize();

        //statue check
        if (bufId > 0 && !CheckEncRequestsCompatibility(req[i - 1], req[i]))
        {
            req[i]->SetCompatibilityStatus(false);
            continue;
        }

        // embed data
        int keySize = 0;
        ippsRSA_GetSizePublicKey(bitSizeN, bitSizeE, &keySize);
        pPubKey[bufId] = (IppsRSAPublicKeyState *)(new Ipp8u[keySize * 2]);
        ippsRSA_InitPublicKey(bitSizeN, bitSizeE, pPubKey[bufId], keySize);
        ippsRSA_SetPublicKey(req[i]->GetValueN(), E, pPubKey[bufId]);
        mbCipherTextArray[bufId] = req[i]->GetCipherText();
        mbPlainTextArray[bufId] = req[i]->GetPlainText();

        bufId++;

        //deal
        int leave = buf;

        if (num % buf != 0 && i == num - 1)
        {
            leave = num % buf;
            while (bufId != buf)
            {
                pPubKey[bufId] = NULL;
                mbCipherTextArray[bufId] = NULL;
                mbPlainTextArray[bufId] = NULL;
                bufId++;
            }
        }

        /* Check if there are enough requests for the operation */
        if (bufId == buf)
        {
            /* Calculate temporary buffer size */
            int pubBufSize = 0;
            status = ippsRSA_MB_GetBufferSizePublicKey(&pubBufSize, pPubKey);
            if (!checkStatus("ippsRSA_MB_GetBufferSizePublicKey", ippStsNoErr, status))
            {
                cout << "Step 1" << endl;
                for (int i = 0; i < leave; i++)
                    delete[](Ipp8u *) pPubKey[i];
                cout << "Step 2" << endl;
                break;
            }

            /* Allocate memory for temporary buffer */
            //Ipp8u *pScratchBuffer = new Ipp8u[pubBufSize * 2];

            /* Encrypt message******************************************************************************/
            //status = ippsRSA_MB_Encrypt(mbPlainTextArray, mbCipherTextArray,
            //    pPubKey, statusesArray,
            //    pScratchBuffer);

            cout << "Step 3" << endl;
            //delete[] pScratchBuffer;
            /* Handling the ippStsMbWarning status when the number of requests in the queue is not a multiple of eight */
            if (leave != buf && status == ippStsMbWarning)
            {
                /* If ippStsNullPtrErr status is in the initially unspecified buffers, then we consider that the status of the operation is ippStsNoErr */
                status = ippStsNoErr;
                for (int j = 0; j < leave; j++)
                    if (statusesArray[j] != ippStsNoErr)
                        status = ippStsMbWarning;
                for (int j = leave; j < buf; j++)
                    if (statusesArray[j] != ippStsNullPtrErr)
                        status = ippStsMbWarning;
            }

            // cout <<"Step 4" << endl;
            for (int j = 0; j < leave; j++)
                delete[](Ipp8u *) pPubKey[j];
            //  cout <<"Step 5" << endl;
            bufId = 0;

            if (!checkStatus("ippsRSA_MB_Encrypt", ippStsNoErr, status))
                break;
        }
    }
    // clock_t end = clock();
    // double tt = (double)(end - str) *1000000/ CLOCKS_PER_SEC;
    // printf("encrypt cost time %lf us  ops(mops) = %lf \n", tt, (double)num / tt);

    //check Decrypt

    bufId = 0;
    clock_t str_avx = clock();
    //auto end1 = system_clock::now();

    /*======================================================= DEC============================================*/
    clock_t str_avx_l, end_avx_l;
    double ttime = 0.f;

    for (int i = 0; i < num; i++)
    {
        //printf("@@@@@@%d \n", i);

        /* Don't process request that did not pass the compatibility check at the encryption stage */
        if (!req[i]->IsCompatible())
            continue;

        bitSizeD = req[i]->GetBitSizeD();
        bitSizeN = req[i]->GetBitSizeN();

        ///* This value should be the same for all eight buffers */
        ///* Allocate memory for private key Type1, all keys should be of the same type */
        ////���� priv key���ڴ�
        int keySize = 0;
        ippsRSA_GetSizePrivateKeyType1(bitSizeN, bitSizeD, &keySize);
        pPrivKey[bufId] = (IppsRSAPrivateKeyState *)(new Ipp8u[keySize * 2]);

        ///* Prepare key to operation */
        ippsRSA_InitPrivateKeyType1(bitSizeN, bitSizeD, pPrivKey[bufId], keySize);

        //RSA: c ^ d % n
        ippsRSA_SetPrivateKeyType1(req[i]->GetValueN(), req[i]->GetValueD(), pPrivKey[bufId]);

        /* Check decryption requests and pPrivKey types compatibility of each eight buffers, if the request is incompatible, mark it as not processed and take another request */
        if (bufId > 0 && (!CheckDecRequestsCompatibility(req[i - 1], req[i]) || !CheckPrivateKeyCompatibility(pPrivKey[bufId - 1], pPrivKey[bufId])))
        {
            //cout <<"Step 6:" << i << endl;
            req[i]->SetCompatibilityStatus(false);
            delete[](Ipp8u *) pPrivKey[bufId];
            // cout <<"Step 7:" << i << endl;
            continue;
        }

        ///* Forming the array of cipher and decipher texts */
        mbDecipherTextArray[bufId] = req[i]->GetDecipherText();
        mbCipherTextArray[bufId] = req[i]->GetCipherText();

        bufId++;

        ///* Handling the case when the number of requests in the queue is not a multiple of eight, initializing insufficient data with zeros */
        int leave = buf;
        if (num % buf != 0 && i == num - 1)
        {
            leave = num % buf;
            while (bufId != buf)
            {
                pPrivKey[bufId] = NULL;
                mbCipherTextArray[bufId] = NULL;
                mbDecipherTextArray[bufId] = NULL;
                bufId++;
            }
        }

        ////decrypt
        leave = 0;
        //printf("bufid = %d buf = %d\n", bufId, buf);

        if (bufId == buf)
        {
            /* Calculate temporary buffer size */
            int privBufSize = 0;
            status = ippsRSA_MB_GetBufferSizePrivateKey(&privBufSize, pPrivKey);
            if (!checkStatus("ippsRSA_MB_GetBufferSizePrivateKey", ippStsNoErr, status))
            {
                cout << "Step 8" << endl;
                printf("ippsRSA_MB_GetBufferSizePrivateKey quit");
                for (int j = 0; j < leave; j++)
                    delete[](Ipp8u *) pPrivKey[j];
                cout << "Step 9: " << privBufSize << endl;
                break;
            }

            auto end5 = system_clock::now();
            /* Allocate memory for temporary buffer */
            //����8�� ����ռ�
            //
            //
            //
            //
            //
            //

            if (ENABLE_GMP)
            {
                int k = i;

                BigNumber _p = req[k]->GetPlainText();
                BigNumber _c = req[k]->GetCipherText();
                BigNumber _d = req[k]->GetDecipherText();
                vector<Ipp32u> _vp;
                vector<Ipp32u> _vc;
                vector<Ipp32u> _vd;
                _p.num2vec(_vp);
                _c.num2vec(_vc);
                _d.num2vec(_vd);

                for (int j = 0; j < 8; j++)
                {
                    printf("222222222222 req = %d: p = %d c = %d d = %d\n", k, _vp[j], _vc[j], _vd[j]);
                }
            }

            printf("XXXXXXXXXXXXXXXXXXX\n");

            Ipp8u *pScratchBuffer = new Ipp8u[privBufSize * privBufSize];
            //    cout <<"Step 10" << endl;
            /* Decrypt message */ //����
            str_avx_l = clock();
            status = ippsRSA_MB_Decrypt(mbCipherTextArray, mbDecipherTextArray,
                                        pPrivKey, statusesArray,
                                        pScratchBuffer);
            end_avx_l = clock();
            ttime += (double)(end_avx_l - str_avx_l);

            printf("XXXXXXXXXXXXXXXXXXX\n");
            //printf("call avx decrypt\n");

            if (ENABLE_GMP)
            {
                int k = i;

                BigNumber _p = req[k]->GetPlainText();
                BigNumber _c = req[k]->GetCipherText();
                BigNumber _d = req[k]->GetDecipherText();
                vector<Ipp32u> _vp;
                vector<Ipp32u> _vc;
                vector<Ipp32u> _vd;
                _p.num2vec(_vp);
                _c.num2vec(_vc);
                _d.num2vec(_vd);

                for (int j = 0; j < 8; j++)
                {
                    printf("333333333333333 k = %d: p = %d c = %d d = %d\n", k, _vp[j], _vc[j], _vd[j]);
                }
            }

            //   printf("status = %d\n", status);
            //  printf("statusesArray[0]=%d\n", statusesArray[0]);
            ///  cout <<"Step 11:" << privBufSize << endl;
            //delete[] pScratchBuffer;
            //cout <<"Step 12" << endl;
            // auto end6 = system_clock::now();
            //  auto duration4 = duration_cast<microseconds>(end6 - end5);
            //  cout <<  "ipp mb decryption= "   << double(duration4.count()) /1000  << "ms" << endl;
            /* Handling the ippStsMbWarning status when the number of requests in the queue is not a multiple of eight */
            if (leave != buf && status == ippStsMbWarning)
            {
                /* If ippStsNullPtrErr status is in the initially unspecified buffers, then we consider that the status of the operation is ippStsNoErr */
                status = ippStsNoErr;
                for (int j = 0; j < leave; j++)
                    if (statusesArray[j] != ippStsNoErr)
                        status = ippStsMbWarning;
                for (int j = leave; j < buf; j++)
                    if (statusesArray[j] != ippStsNullPtrErr)
                        status = ippStsMbWarning;
            }
            // cout <<"Step 12" << endl;
            for (int j = 0; j < leave; j++)
                delete[](Ipp8u *) pPrivKey[j];
            //cout <<"Step 13" << endl;
            bufId = 0;

            if (!checkStatus("ippsRSA_MB_Decrypt", ippStsNoErr, status))
                break;
        }
    }

    clock_t end_avx = clock();
    double tt = (double)(end_avx - str_avx) / CLOCKS_PER_SEC;
    printf("decrypt avx cost time %lf ms \n", tt * 1000.f);
    printf("decrypt avx func cost time %lf ms \n", (ttime / (CLOCKS_PER_SEC)) * 1000.f);

    //    auto end2 = system_clock::now();
    //    auto duration1 = duration_cast<microseconds>(end1 - start);
    //    auto duration2 = duration_cast<microseconds>(end2 - end1);
    //    cout <<  "ipp encryption= "   << double(duration1.count()) /1000  << "ms" << endl;
    //    cout <<  "ipp decryption= "   << double(duration2.count()) /1000  << "ms" << endl;
    //
    //check Decrypt
    if (0) //CK_DE)
    {
        clock_t str_gmp = clock();
        clock_t str_gmp_l, end_gmp_l;
        double ttime_gmp = 0.f;
        for (int i = 0; i < num; i++)
        {
            BigNumber d = _D1;
            BigNumber n = _N1;
            BigNumber ciper = req[i]->GetCipherText();
            // BigNumber ciper = BigNumber(mbCipherTextArray[i % 8]);//req[i]->GetCipherText();
            BigNumber comp = req[i]->GetDecipherText();
            //  BigNumber comp = BigNumber(mbDecipherTextArray[i % 8]); //req[i]->GetDecipherText();

            mpz_t g_res, g_n, g_d, g_comp, g_cipher;
            mpz_init(g_res);
            mpz_init(g_n);
            mpz_init(g_d);
            mpz_init(g_comp);
            mpz_init(g_cipher);

            num2gmp(d, g_d);
            num2gmp(n, g_n);
            num2gmp(comp, g_comp);
            num2gmp(ciper, g_cipher);
            auto end3 = system_clock::now();
            //if(i >=8)
            str_gmp_l = clock();
            rsa(g_res, g_cipher, g_d, g_n, 0);
            end_gmp_l = clock();
            ttime_gmp += (double)(end_gmp_l - str_gmp_l);
            //else
            //	rsa(g_res, g_cipher, g_d, g_n, 10);

            //	    auto end4 = system_clock::now();
            //            auto duration3 = duration_cast<microseconds>(end4 - end3);
            //            cout <<  "gmp decryption= "   << double(duration3.count()) /1000  << "ms" << endl;

            //cmp cipher
            int error = mpzComp(g_res, g_comp);
            if (error == -1)
            {
                printf("error appear %d time\n", i);
                vector<Ipp32u> tmp;
                comp.num2vec(tmp);
                g_printf(g_res, tmp);

                printf("decry1 errrrrrrrrrrr %d\n ", i);
                cout << "After decry, ciper buffer:" << ciper << endl;
                cout << "After decry, decipher buffer:" << comp << endl;
                return 0;
            }

            //clear
            mpz_clear(g_d);
            mpz_clear(g_n);
            mpz_clear(g_comp);
            mpz_clear(g_res);
            mpz_clear(g_cipher);
        }
        clock_t end_gmp = clock();
        double tt = (double)(end_gmp - str_gmp) / CLOCKS_PER_SEC;
        printf("decrypt gmp cost time %lf ms \n", tt * 1000.f);
        printf("decrypt gmp func cost time %lf ms \n", (ttime_gmp / (CLOCKS_PER_SEC)) * 1000.f);
    }

    PRINT_EXAMPLE_STATUS("ippsRSA_MB_Encrypt, ippsRSA_MB_Decrypt", "RSA MULTI BUFFER 1024 Encryption and Decryption", ippStsNoErr == status);

    return 0;
}

int powm_avx(fate_bignum* res, fate_bignum* b, fate_bignum* e, fate_bignum* m, int num)
{
    /*CCCC**/
    assert(res->ismalloc == 1);
    assert(b->ismalloc == 1);
    assert(e->ismalloc == 1);
    assert(m->ismalloc == 1);

    assert(res->num == b->num);
    assert(e->num == b->num);
    assert(m->num == b->num);


    const int buf = 8;
    const int crypt = 10;

    if (num % buf != 0)
        return 0;

    Request** req = (Request**)malloc(sizeof(void*) * num);
    clock_t str = clock();
    int idx;


    for (int i = 0; i < num; i++)
    {
        req[i] = new Request(gmp2num(b->bigint[i]), gmp2num(m->bigint[i]), _E,\
            gmp2num(e->bigint[i]));
    }

    IppStatus status = ippStsNoErr;
    IppStatus statusesArray[buf];

    IppsRSAPublicKeyState* pPubKey[buf];
    IppsRSAPrivateKeyState* pPrivKey[buf];
    IppsBigNumState* mbPlainTextArray[buf];
    IppsBigNumState* mbCipherTextArray[buf];
    IppsBigNumState* mbDecipherTextArray[buf];

    int bitSizeN, bitSizeE, bitSizeD;
    int bufId = 0;

    if (ENABLE_GMP)
    {
        BigNumber _p = req[0]->GetPlainText();
        BigNumber _c = req[0]->GetCipherText();
        BigNumber _d = req[0]->GetDecipherText();
        vector<Ipp32u> _vp;
        vector<Ipp32u> _vc;
        vector<Ipp32u> _vd;
        _p.num2vec(_vp);
        _c.num2vec(_vc);
        _d.num2vec(_vd);
        for (int i = 0; i < 8; i++)
        {
            printf("11111111 p = %d c = %d d = %d\n", _vp[i], _vc[i], _vd[i]);
        }
    }
    /*========================================================= ENC =================================================*/

    for (int i = 0; i < num; i++)
    {
        bitSizeN = req[i]->GetBitSizeN();
        bitSizeE = _E.BitSize();

        //statue check
        if (bufId > 0 && !CheckEncRequestsCompatibility(req[i - 1], req[i]))
        {
            req[i]->SetCompatibilityStatus(false);
            continue;
        }

        // embed data
        int keySize = 0;
        ippsRSA_GetSizePublicKey(bitSizeN, bitSizeE, &keySize);
        pPubKey[bufId] = (IppsRSAPublicKeyState*)(new Ipp8u[keySize * 2]);
        ippsRSA_InitPublicKey(bitSizeN, bitSizeE, pPubKey[bufId], keySize);
        ippsRSA_SetPublicKey(req[i]->GetValueN(), E, pPubKey[bufId]);
        mbCipherTextArray[bufId] = req[i]->GetCipherText();
        mbPlainTextArray[bufId] = req[i]->GetPlainText();

        bufId++;

        //deal
        int leave = buf;

        if (num % buf != 0 && i == num - 1)
        {
            leave = num % buf;
            while (bufId != buf)
            {
                pPubKey[bufId] = NULL;
                mbCipherTextArray[bufId] = NULL;
                mbPlainTextArray[bufId] = NULL;
                bufId++;
            }
        }

        /* Check if there are enough requests for the operation */
        if (bufId == buf)
        {
            /* Calculate temporary buffer size */
            int pubBufSize = 0;
            status = ippsRSA_MB_GetBufferSizePublicKey(&pubBufSize, pPubKey);
            if (!checkStatus("ippsRSA_MB_GetBufferSizePublicKey", ippStsNoErr, status))
            {
                cout << "Step 1" << endl;
                for (int i = 0; i < leave; i++)
                    delete[](Ipp8u*) pPubKey[i];
                cout << "Step 2" << endl;
                break;
            }

            /* Handling the ippStsMbWarning status when the number of requests in the queue is not a multiple of eight */
            if (leave != buf && status == ippStsMbWarning)
            {
                /* If ippStsNullPtrErr status is in the initially unspecified buffers, then we consider that the status of the operation is ippStsNoErr */
                status = ippStsNoErr;
                for (int j = 0; j < leave; j++)
                    if (statusesArray[j] != ippStsNoErr)
                        status = ippStsMbWarning;
                for (int j = leave; j < buf; j++)
                    if (statusesArray[j] != ippStsNullPtrErr)
                        status = ippStsMbWarning;
            }

            // cout <<"Step 4" << endl;
            for (int j = 0; j < leave; j++)
                delete[](Ipp8u*) pPubKey[j];
            //  cout <<"Step 5" << endl;
            bufId = 0;

            if (!checkStatus("ippsRSA_MB_Encrypt", ippStsNoErr, status))
                break;
        }
    }

    /*======================================================= DEC============================================*/
    bufId = 0;
    clock_t str_avx = clock();
    clock_t str_avx_l, end_avx_l;
    double ttime = 0.f;

    for (int i = 0; i < num; i++)
    {
        /* Don't process request that did not pass the compatibility check at the encryption stage */
        if (!req[i]->IsCompatible())
            continue;

        bitSizeD = req[i]->GetBitSizeD();
        bitSizeN = req[i]->GetBitSizeN();

        //// priv key
        int keySize = 0;
        ippsRSA_GetSizePrivateKeyType1(bitSizeN, bitSizeD, &keySize);
        pPrivKey[bufId] = (IppsRSAPrivateKeyState*)(new Ipp8u[keySize * 2]);

        ///* Prepare key to operation */
        ippsRSA_InitPrivateKeyType1(bitSizeN, bitSizeD, pPrivKey[bufId], keySize);

        //RSA: c ^ d % n
        ippsRSA_SetPrivateKeyType1(req[i]->GetValueN(), req[i]->GetValueD(), pPrivKey[bufId]);

        /* Check decryption requests and pPrivKey types compatibility of each eight buffers, if the request is incompatible, mark it as not processed and take another request */
        if (bufId > 0 && (!CheckDecRequestsCompatibility(req[i - 1], req[i]) || !CheckPrivateKeyCompatibility(pPrivKey[bufId - 1], pPrivKey[bufId])))
        {
            //cout <<"Step 6:" << i << endl;
            req[i]->SetCompatibilityStatus(false);
            delete[](Ipp8u*) pPrivKey[bufId];
            // cout <<"Step 7:" << i << endl;
            continue;
        }

        ///* Forming the array of cipher and decipher texts */
        mbDecipherTextArray[bufId] = req[i]->GetDecipherText();
        mbCipherTextArray[bufId] = req[i]->GetCipherText();

        bufId++;

        ///* Handling the case when the number of requests in the queue is not a multiple of eight, initializing insufficient data with zeros */
        int leave = buf;
        if (num % buf != 0 && i == num - 1)
        {
            leave = num % buf;
            while (bufId != buf)
            {
                pPrivKey[bufId] = NULL;
                mbCipherTextArray[bufId] = NULL;
                mbDecipherTextArray[bufId] = NULL;
                bufId++;
            }
        }

        ////decrypt
        leave = 0;

        if (bufId == buf)
        {
            /* Calculate temporary buffer size */
            int privBufSize = 0;
            status = ippsRSA_MB_GetBufferSizePrivateKey(&privBufSize, pPrivKey);
            if (!checkStatus("ippsRSA_MB_GetBufferSizePrivateKey", ippStsNoErr, status))
            {
                cout << "Step 8" << endl;
                printf("ippsRSA_MB_GetBufferSizePrivateKey quit");
                for (int j = 0; j < leave; j++)
                    delete[](Ipp8u*) pPrivKey[j];
                cout << "Step 9: " << privBufSize << endl;
                break;
            }

            if (ENABLE_GMP)
            {
                int k = i;

                BigNumber _p = req[k]->GetPlainText();
                BigNumber _c = req[k]->GetCipherText();
                BigNumber _d = req[k]->GetDecipherText();
                vector<Ipp32u> _vp;
                vector<Ipp32u> _vc;
                vector<Ipp32u> _vd;
                _p.num2vec(_vp);
                _c.num2vec(_vc);
                _d.num2vec(_vd);

                for (int j = 0; j < 8; j++)
                {
                    printf("222222222222 req = %d: p = %d c = %d d = %d\n", k, _vp[j], _vc[j], _vd[j]);
                }
            }

            printf("XXXXXXXXXXXXXXXXXXX\n");

            Ipp8u* pScratchBuffer = new Ipp8u[privBufSize * privBufSize];
            //    cout <<"Step 10" << endl;
            /* Decrypt message */ //����
            str_avx_l = clock();
            status = ippsRSA_MB_Decrypt(mbCipherTextArray, mbDecipherTextArray,
                pPrivKey, statusesArray,
                pScratchBuffer);
            end_avx_l = clock();
            ttime += (double)(end_avx_l - str_avx_l);

            printf("XXXXXXXXXXXXXXXXXXX\n");
            //printf("call avx decrypt\n");

            if (ENABLE_GMP)
            {
                int k = i;

                BigNumber _p = req[k]->GetPlainText();
                BigNumber _c = req[k]->GetCipherText();
                BigNumber _d = req[k]->GetDecipherText();
                vector<Ipp32u> _vp;
                vector<Ipp32u> _vc;
                vector<Ipp32u> _vd;
                _p.num2vec(_vp);
                _c.num2vec(_vc);
                _d.num2vec(_vd);

                for (int j = 0; j < 8; j++)
                {
                    printf("333333333333333 k = %d: p = %d c = %d d = %d\n", k, _vp[j], _vc[j], _vd[j]);
                }
            }
     
            if (leave != buf && status == ippStsMbWarning)
            {
                /* If ippStsNullPtrErr status is in the initially unspecified buffers, then we consider that the status of the operation is ippStsNoErr */
                status = ippStsNoErr;
                for (int j = 0; j < leave; j++)
                    if (statusesArray[j] != ippStsNoErr)
                        status = ippStsMbWarning;
                for (int j = leave; j < buf; j++)
                    if (statusesArray[j] != ippStsNullPtrErr)
                        status = ippStsMbWarning;
            }
            for (int j = 0; j < leave; j++)
                delete[](Ipp8u*) pPrivKey[j];
            bufId = 0;

            if (!checkStatus("ippsRSA_MB_Decrypt", ippStsNoErr, status))
                break;
        }
    }

    clock_t end_avx = clock();
    double tt = (double)(end_avx - str_avx) / CLOCKS_PER_SEC;
    printf("decrypt avx cost time %lf ms \n", tt * 1000.f);
    printf("decrypt avx func cost time %lf ms \n", (ttime / (CLOCKS_PER_SEC)) * 1000.f);
   
    return 0;
}


int main()
{
    int testNum = 8;

    fate_bignum* fate_b = (fate_bignum*)malloc(sizeof(fate_bignum));
    fate_bignum* fate_e = (fate_bignum*)malloc(sizeof(fate_bignum));
    fate_bignum* fate_m = (fate_bignum*)malloc(sizeof(fate_bignum));
    fate_bignum* fate_res_avx = (fate_bignum*)malloc(sizeof(fate_bignum));
    fate_bignum* fate_res_gmp = (fate_bignum*)malloc(sizeof(fate_bignum));
   
    fate_b->bigint = (mpz_t*)malloc(sizeof(mpz_t) * testNum);
    fate_e->bigint = (mpz_t*)malloc(sizeof(mpz_t) * testNum);
    fate_m->bigint = (mpz_t*)malloc(sizeof(mpz_t) * testNum);
    fate_res_avx->bigint = (mpz_t*)malloc(sizeof(mpz_t) * testNum);
    fate_res_gmp->bigint = (mpz_t*)malloc(sizeof(mpz_t) * testNum);

    gmp_randstate_t state;
    gmp_randinit_default(state);         
    gmp_randseed_ui(state, clock());

    //malloc
    for (int  i = 0; i < testNum; i++)
    {

        mpz_init(fate_b->bigint[i]);
        mpz_init(fate_e->bigint[i]);
        mpz_init(fate_m->bigint[i]);
        mpz_init(fate_res_avx->bigint[i]);
        mpz_init(fate_res_gmp->bigint[i]);

     /*   mpz_setbit(fate_b->bigint[i], 1023);
        mpz_setbit(fate_e->bigint[i], 1023);
        mpz_setbit(fate_m->bigint[i], 1023);
        mpz_setbit(fate_res_avx->bigint[i], 1023);

        genrand_gmp(fate_b->bigint[i]);
        genrand_gmp(fate_e->bigint[i]);
        genrand_gmp(fate_m->bigint[i]);*/


        mpz_rrandomb(fate_b->bigint[i], state, 1024);
        mpz_rrandomb(fate_e->bigint[i], state, 1024);
        mpz_rrandomb(fate_m->bigint[i], state, 1024);


    }
    //gmp_printf("%Zd\n", fate_b->bigint[i]);

    //printf("[%d] %d \n", i, fate_b->bigint[i]->_mp_size);


    fate_b->ismalloc = 1;
    fate_e->ismalloc = 1;
    fate_m->ismalloc = 1;
    fate_res_avx->ismalloc = 1;
    fate_res_gmp->ismalloc = 1;

    fate_b->num = testNum;
    fate_e->num = testNum;
    fate_m->num = testNum;
    fate_res_avx->num = testNum;
    fate_res_gmp->num = testNum;

    ////avx
    clock_t str = clock();
    powm_avx(fate_res_avx, fate_b, fate_e, fate_m, testNum);
    clock_t end = clock();
    printf("avx cost time = %lf ms\n", \
        (((double)end - (double)str) / CLOCKS_PER_SEC) * (1000.f));


    //gmp
    str = clock();
    for (int i = 0; i < testNum; i++)
    {
        rsa(fate_res_gmp->bigint[i], fate_b->bigint[i], \
            fate_e->bigint[i], fate_m->bigint[i], 0);
    }
    end = clock();
    printf("gmp cost time = %lf ms\n", \
        (((double)end - (double)str) / CLOCKS_PER_SEC) * (1000.f));



    //gmp_printf("%Zd\n", fate_res_avx->bigint[0]);
    gmp_printf("%Zd\n", fate_res_gmp->bigint[0]);

    //comp
    //for (int i = 0; i < testNum; i++)
    //{
    //    assert(0 == mpz_cmp(fate_res_avx->bigint[i], fate_res_gmp->bigint[i]));
    //}

    ////free
    //for (int i = 0; i < testNum; i++)
    //{
    //    mpz_clear(fate_b->bigint[i]);
    //    mpz_clear(fate_e->bigint[i]);
    //    mpz_clear(fate_m->bigint[i]);
    //    mpz_clear(fate_res_avx->bigint[i]);
    //    mpz_clear(fate_res_gmp->bigint[i]);
    //}
    //free(fate_b);
    //free(fate_e);
    //free(fate_m);
    //free(fate_res_avx);
    //free(fate_res_gmp);

    return 0;
}