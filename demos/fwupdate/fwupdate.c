/**************************************************************************//**
* @file     fwupdate.c
* @version  V1.00
* @brief    The program can flash pack file is produced by Nuvoton NuWriter.
*
* SPDX-License-Identifier: Apache-2.0
*
* Change Logs:
* Date            Author           Notes
* 2020-7-14       Wayne            First version
*
******************************************************************************/

#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <error.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/utsname.h>
#include <getopt.h>

#include <mtd/mtd-user.h>

#define NUWRITER_PACK_INITIAL_MARKER 0x00000005

#define TRUE 1
#define FALSE 0

/* Structure of NuWriter Packfile Header */
typedef struct
{
    unsigned int m_ui32InitialMarker;
    unsigned int m_ui32FileLength;
    unsigned int m_ui32FileNumber;
    unsigned int m_ui32Reserve;
} S_NUWRITER_PACK_HDR;

/* Structure of NuWriter Child in pack Header */
typedef struct
{
    unsigned int m_ui32FileLength;
    unsigned int m_ui32FlashAddress;
    unsigned int m_ui32ImageType;
    unsigned int m_ui32Reserve;
} S_NUWRITER_PACK_CHILDFILE;

/* Static variables */
static S_NUWRITER_PACK_HDR g_sNuWriterPackHdr = {0xff};
static S_NUWRITER_PACK_CHILDFILE *g_psNuWriterPackChildFiles = NULL;
static int *g_psNuWriterPackChildFileOffset = NULL;

static FILE *g_fpNuWriterPackImg = NULL;
struct mtd_info_user g_sWholeMtdInfo;

static char g_SZPackFileName[256] = {0};
static char g_SZWholePartitionName[64] = {'W', 'H', 'O', 'L', 'E'};

static int mtd_open(const char *mtd, int flags)
{
    FILE *fp;

    if ((fp = fopen("/proc/mtd", "r")))
    {
        char dev[PATH_MAX];
        while (fgets(dev, sizeof(dev), fp))
        {
            int i;
            if (sscanf(dev, "mtd%d:", &i) && strstr(dev, mtd))
            {
                snprintf(dev, sizeof(dev), "/dev/mtd%d", i);
                fclose(fp);
                return open(dev, flags);
            }
        }
        fclose(fp);
    }

    return -1;
}

static void nuwriter_pack_image_info_dump(void)
{
    int i = 0;

    printf("Header\n");
    printf("\tInitial marker: %08x \n", g_sNuWriterPackHdr.m_ui32InitialMarker);
    printf("\tFile Length: %u \n", g_sNuWriterPackHdr.m_ui32FileLength);
    printf("\tFile number: %u \n", g_sNuWriterPackHdr.m_ui32FileNumber);
    printf("\tReserve: %08xH \n", g_sNuWriterPackHdr.m_ui32Reserve);

    for (i = 0; i < g_sNuWriterPackHdr.m_ui32FileNumber; i++)
    {
        printf("Child-%d\n", i);
        printf("\tFile length: %u \n", g_psNuWriterPackChildFiles[i].m_ui32FileLength);
        printf("\tFlash address: %08x \n", g_psNuWriterPackChildFiles[i].m_ui32FlashAddress);
        printf("\tImage type: %u \n", g_psNuWriterPackChildFiles[i].m_ui32ImageType);
        printf("\tReserve: %08xH \n", g_psNuWriterPackChildFiles[i].m_ui32Reserve);
    }
}

static void fwupdate_mtd_info_user_dump(struct mtd_info_user *pmtdInfo)
{
    printf("WHOLE\n");
    printf("\ttype: %d \n", pmtdInfo->type);
    printf("\tflags: %08x \n", pmtdInfo->flags);
    printf("\tsize: %d \n", pmtdInfo->size);
    printf("\terasesize: %08xH \n", pmtdInfo->erasesize);
    printf("\twritesize: %08xH \n", pmtdInfo->writesize);
    printf("\toobsize: %08xH \n", pmtdInfo->oobsize);
}

static int nuwriter_pack_init(char *image_path)
{
    int count = 0;
    int childfile_len = 0;
    int file_offset;

    /* Open pack image file. */
    g_fpNuWriterPackImg = fopen(image_path, "rb");
    if (g_fpNuWriterPackImg == NULL)
    {
        printf("Open read File Error(-w %s) \n", image_path);
        goto fail_nuwriter_pack_init;
    }

    /* Check Initial Marker */
    fread((unsigned char *)&g_sNuWriterPackHdr, sizeof(S_NUWRITER_PACK_HDR), 1, g_fpNuWriterPackImg);
    if (g_sNuWriterPackHdr.m_ui32InitialMarker != NUWRITER_PACK_INITIAL_MARKER)
    {
        printf("Pack Image Format Error\n");
        goto fail_nuwriter_pack_init;
    }

    /* Open pack image file. */
    g_psNuWriterPackChildFiles = malloc(g_sNuWriterPackHdr.m_ui32FileNumber * sizeof(S_NUWRITER_PACK_CHILDFILE));
    if (g_psNuWriterPackChildFiles == NULL)
    {
        printf("Failed to allocate memory for child file array.\n");

        goto fail_nuwriter_pack_init;
    }
    memset((void *)&g_psNuWriterPackChildFiles[0], 0, g_sNuWriterPackHdr.m_ui32FileNumber * sizeof(S_NUWRITER_PACK_CHILDFILE));

    /* Resource for children */
    g_psNuWriterPackChildFileOffset = malloc(g_sNuWriterPackHdr.m_ui32FileNumber * sizeof(int));
    if (g_psNuWriterPackChildFileOffset == NULL)
    {
        printf("Failed to allocate memory for child file address array.\n");

        goto fail_nuwriter_pack_init;
    }

    /* Read child file to array */
    while (count < g_sNuWriterPackHdr.m_ui32FileNumber)
    {
        file_offset = sizeof(S_NUWRITER_PACK_HDR) + count * sizeof(S_NUWRITER_PACK_CHILDFILE) + childfile_len;

        g_psNuWriterPackChildFileOffset[count] = file_offset + sizeof(S_NUWRITER_PACK_CHILDFILE);

        fseek(g_fpNuWriterPackImg, file_offset, SEEK_SET);

        fread((unsigned char *)&g_psNuWriterPackChildFiles[count], sizeof(S_NUWRITER_PACK_CHILDFILE), 1, g_fpNuWriterPackImg);

        childfile_len += g_psNuWriterPackChildFiles[count].m_ui32FileLength;

        count++;
    }

    return 0;

fail_nuwriter_pack_init:

    if (g_fpNuWriterPackImg)
        fclose(g_fpNuWriterPackImg);

    g_fpNuWriterPackImg = NULL;

    return -1;
}


long int getFileLen(FILE *in)
{
    long int len;
    fseek(in, 0, SEEK_END);
    len = ftell(in);
    rewind(in);
    printf("The file size is %ld bytes\n", len);
    return len;
}


static int mtd_check(const char *mtd, struct mtd_info_user *pmtdInfo)
{
    int ret = -1;
    int fd;

    if ((fd = mtd_open(mtd, O_RDONLY)) < 0)
    {
        fprintf(stderr, "Can not open WHOLE mtd device\n");
        goto exit_mtd_check;
    }

    if ((ret = ioctl(fd, MEMGETINFO, pmtdInfo)) < 0)
    {
        fprintf(stderr, "Can not get MTD device info from WHOLE mtd device\n");
        goto exit_mtd_check;
    }

    ret = 0;

exit_mtd_check:

    if (fd >= 0)
        close(fd);

    return ret;
}

static int mtd_erase(const char *mtd, uint32_t address, int len)
{
    int ret = -1;
    int fd ;

    struct erase_info_user mtdEraseInfo;

    fd = mtd_open(mtd, O_RDWR | O_SYNC);
    if (fd < 0)
    {
        goto exit_mtd_erase;
    }

    mtdEraseInfo.length = g_sWholeMtdInfo.erasesize;

    for (mtdEraseInfo.start = address;
            mtdEraseInfo.start < address + len;
            mtdEraseInfo.start += g_sWholeMtdInfo.erasesize)
    {

        ioctl(fd, MEMUNLOCK, &mtdEraseInfo);
        if (ioctl(fd, MEMERASE, &mtdEraseInfo))
        {
            goto exit_mtd_erase;
        }

    }

    ret = 0;

exit_mtd_erase:

    if (fd >= 0)
        close(fd);

    return ret;
}

static int mtd_write(const char *mtd, unsigned int flash_offset, unsigned int file_offset, unsigned int len)
{
    int fd = -1;
    int ret = -1;
    char *buf = NULL;
    int isNANDflash = (g_sWholeMtdInfo.oobsize > 0);
    int i32WriteSize;

    if (!g_fpNuWriterPackImg)
        return -1;

    if (fseek(g_fpNuWriterPackImg, file_offset, SEEK_SET) != 0)
    {
        printf("Can't seek.(%d)\n", errno);
        goto exit_mtd_write;
    }

    fd = mtd_open(mtd, O_RDWR | O_SYNC);
    if (fd < 0)
    {
        fprintf(stderr, "Could not open mtd device\n");
        goto exit_mtd_write;
    }

    if (lseek(fd, flash_offset, SEEK_SET) != flash_offset)
    {
        printf("Can't lseek.(%d)\n", errno);
        goto exit_mtd_write;
    }

    if (isNANDflash)
        i32WriteSize = g_sWholeMtdInfo.writesize;
    else
        i32WriteSize = g_sWholeMtdInfo.erasesize;

    if ((buf = malloc(i32WriteSize)) == NULL)
    {
        printf("Can't malloc.(%d)\n", errno);
        goto exit_mtd_write;
    }

    memset((void *)&buf[0], 0xff, i32WriteSize);

    while (len > 0)
    {
        int result;
        int session_size;
        size_t r;

        /* buffer may contain data already (from imghdr check) */
        session_size = MIN(len, i32WriteSize);

        if (session_size != i32WriteSize)
            memset((void *)&buf[0], 0xff, i32WriteSize);

        r = fread((unsigned char *)&buf[0], session_size, 1, g_fpNuWriterPackImg) * session_size;
        len -= r;

        /* EOF */
        if (r == 0) break;

        if ((result = write(fd, &buf[0], i32WriteSize)) < i32WriteSize)
        {
            if (result < 0)
            {
                fprintf(stderr, "Error writing image.\n");
                goto exit_mtd_write;
            }
            else
            {
                fprintf(stderr, "Insufficient space.\n");
                goto exit_mtd_write;
            }
        }

    }

    ret = 0;

exit_mtd_write:

    if (fd >= 0)
        close(fd);

    if (buf)
        free(buf);

    return ret;
}

static int find_whole_partition_entry(const char *mtd)
{
    memset((void *)&g_sWholeMtdInfo, 0, sizeof(struct mtd_info_user));

    if (mtd_check(mtd, &g_sWholeMtdInfo) < 0)
        return FALSE;

    return TRUE;
}


static int pack_child_program(const char *mtd, int idx)
{
    int erase_size = 0;

    /* Not default, it implies it is with erasing block number. */
    if (g_psNuWriterPackChildFiles[idx].m_ui32Reserve != 0xffffffff)
        erase_size = g_psNuWriterPackChildFiles[idx].m_ui32Reserve * g_sWholeMtdInfo.erasesize;
    else
        erase_size = g_psNuWriterPackChildFiles[idx].m_ui32FileLength;

    if (mtd_erase(mtd, g_psNuWriterPackChildFiles[idx].m_ui32FlashAddress, erase_size) < 0)
    {
        printf("[%s] failed to mtd_erase\n", __func__);
        return -1;
    }

    if (mtd_write(mtd, g_psNuWriterPackChildFiles[idx].m_ui32FlashAddress,
                  g_psNuWriterPackChildFileOffset[idx],
                  g_psNuWriterPackChildFiles[idx].m_ui32FileLength) < 0)
    {
        printf("[%s] failed to mtd_write\n", __func__);
        return -1;
    }

    return 0;
}

static int nuwriter_pack_update(const char *mtd)
{
    int i = 0;
    int ret = 0;

    /* Data first */
    for (i = 0; i < g_sNuWriterPackHdr.m_ui32FileNumber; i++)
    {
        if (g_psNuWriterPackChildFiles[i].m_ui32ImageType < 1)
        {
            ret = pack_child_program(mtd, i);
            if (ret != 0)
                goto exit_nuwriter_pack_update;
        }
    }

    /* env, boot */
    for (i = 0; i < g_sNuWriterPackHdr.m_ui32FileNumber; i++)
    {
        if (g_psNuWriterPackChildFiles[i].m_ui32ImageType > 0)
        {
            ret = pack_child_program(mtd, i);
            if (ret != 0)
                goto exit_nuwriter_pack_update;
        }
    }

    return 0;

exit_nuwriter_pack_update:

    return -1;
}

static void help(void)
{
    fprintf(stdout,
            "fwupdate - Flash pack file is created by NuWriter utility. \n"
            "Usage:\n"
            "-p,    --pack      Path of pack file Help.\n"
            "-w,    --whole     Name of MTD partition.\n"
            "-h,    --help      Help.\n"
            "\n");
    fflush(stdout);
}

int main(int argc, char *argv[])
{
    int opt;

    struct option long_option[] =
    {
        {"pack",    required_argument, NULL, 'p'},
        {"whole",    required_argument, NULL, 'w'},
        {"help",    0, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    while ((opt = getopt_long(argc, argv, "p:w:h", long_option, NULL)) >= 0)
    {
        switch (opt)
        {
        case 'p':
            printf("Pack file: '%s'\n", optarg);
            strncpy(g_SZPackFileName, optarg, sizeof(g_SZPackFileName));
            g_SZPackFileName[sizeof(g_SZPackFileName) - 1] = '\0';
            break;

        case 'w':
            printf("Whole partition: '%s'\n", optarg);
            strncpy(g_SZWholePartitionName, optarg, sizeof(g_SZWholePartitionName));
            g_SZWholePartitionName[sizeof(g_SZWholePartitionName) - 1] = '\0';
            break;

        case 'h':
            help();
            return 0;

        default:
            help();
            return -1;
        }
    }

    /* Parse pack file. */
    if (nuwriter_pack_init(g_SZPackFileName) < 0)
    {
        printf("Failed to nuwriter_pack_init\n");
        return -1;
    }

    /* Dump information */
    nuwriter_pack_image_info_dump();

    /* Check WHOLE partition is valid */
    if (!find_whole_partition_entry(g_SZWholePartitionName))
    {
        printf("Failed to find_whole_partition_entry\n");
        return -1;
    }
    /* Dump information of WHOLE partition */
    fwupdate_mtd_info_user_dump(&g_sWholeMtdInfo);

    /* Update */
    return nuwriter_pack_update(g_SZWholePartitionName);
}
