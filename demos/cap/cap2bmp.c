/*
 *  V4L2 video capture example
 *
 *  This program can be used and distributed without restrictions.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>             /* getopt_long() */
#include <fcntl.h>              /* low-level i/o */
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <linux/videodev2.h>

#define NONE_COMP		0 	//0¡G¥¼À£ÁY
#define RLE_8BIT		1	//1¡GRLE 8-bit/pixel
#define RLE_4BIT		2	//2¡GRLE 4-bit/pixel
#define BI_BITFIELDS		3	//3¡GBitfields

#define XRGB888			32
#define RGB888			24
#define RGB565			16

#define GET_FRAME 10

#define CLEAR(x) memset (&(x), 0, sizeof (x))

struct buffer {
	void * start;
	size_t length;
};

#pragma pack(1)
typedef struct tagBITMAPFILEHEADER {	//total=14
	unsigned short 	bfType;		//2
	unsigned int 	bfSize;		//4
	unsigned short 	bfReserved1;	//2
	unsigned short 	bfReserved2;	//2
	unsigned int 	bfOffBits;	//4
} BITMAPFILEHEADER; //BITMAPFILEHEADER;

typedef struct tagBITMAPINFOHEADER {			//total= 28
	unsigned int biSize;				//4
	unsigned int 	biWidth;			//4
	unsigned int 	biHeight;			//4
	unsigned short 	biPlanes;			//2
	unsigned short  biBitCount;			//2
	unsigned int	biCompression;			//4
	unsigned int	biSizeImage;			//4
	unsigned int	biXPelsPerMeter;		//4
	unsigned int 	biYPelsPerMeter;		//4
	unsigned int biClrUsed;				//4
	unsigned int biClrImportant; 			//4
} BITMAPINFOHEADER; //BITMAPINFOHEADER;
#pragma pack()

static char * dev_name = NULL;
static unsigned int dev_fmt = 0;
static int fd = -1;
static int lcmd = -1;
struct buffer * buffers = NULL;
static unsigned int n_buffers = 0;
static int bypass = 0;


#define IN_WIDTH	640
#define IN_HEIGHT	480
#define OUT_WIDTH	320
#define OUT_HEIGHT	240

unsigned char TmpBuffer[OUT_WIDTH*OUT_HEIGHT*3];
static void errno_exit(const char * s)
{
	printf("%s error %d, %s\n", s, errno, strerror(errno));
	exit(EXIT_FAILURE);
}

static int xioctl(int fd, int request, void * arg)
{
	int r;

	do {
		r = ioctl(fd, request, arg);
	} while (-1 == r && EINTR == errno);

	return r;
}

/* RGB Order seem wrong. But content ==> LMH=(BGR)*/
unsigned int RGBToRGB888(unsigned int u32OnePixel,	//Input one RGB pixel
                         unsigned int* pu32OutPixel)	//Out one RGB888 pixel
{

	unsigned int R, G, B;
	//RGB565 to RGB888
	B = (u32OnePixel&0x1F)<<3;
	G = (u32OnePixel&0x7E0)>>3;		//>>5 <<2
	R = (u32OnePixel&0xF800)>>8;		//>>11 <<3
	*pu32OutPixel = (R<<16)|(G<<8)|B;

	return 0;
}

int32_t WriteBitmapFileHeader(FILE* fd,
                              int32_t n32SrcWidth,	/* Source Width */
                              int32_t n32SrcHeight)	/* Source Height */
{
	int i32Ret = 0;
	int u32WriteLen;

	unsigned short		bitCount = RGB888;
	BITMAPFILEHEADER 	s_bmpFileHeader;
	BITMAPINFOHEADER 	s_bmpInfoHeader = { 0 };
	//mask
	unsigned int 				dwMask[3];

	//bitmap file header
	s_bmpFileHeader.bfType = 0x4d42;
	s_bmpFileHeader.bfSize = n32SrcWidth*n32SrcHeight*3+0x36;	//Image Data + file header
	s_bmpFileHeader.bfReserved1 = 0;
	s_bmpFileHeader.bfReserved2 = 0;
	s_bmpFileHeader.bfOffBits = sizeof (BITMAPFILEHEADER) +		//OK ==> 0x0E (4+4+2+2+2=14)
	                            sizeof (BITMAPINFOHEADER);		//OK ==> 0x28
	// 0xE + 0x28 = 0x36

	dwMask[0] = 0x0000f800;
	dwMask[1] = 0x000007e0;
	dwMask[2] = 0x0000001f;

	//bitmap info header
	s_bmpInfoHeader.biBitCount = bitCount;
	s_bmpInfoHeader.biHeight = -n32SrcHeight;
	s_bmpInfoHeader.biWidth = n32SrcWidth;
	s_bmpInfoHeader.biPlanes = 1;
	s_bmpInfoHeader.biSize = sizeof(BITMAPINFOHEADER);
	s_bmpInfoHeader.biCompression = NONE_COMP;//BI_BITFIELDS;
	s_bmpInfoHeader.biSizeImage	= n32SrcHeight*n32SrcWidth*3; //RGB888 image data size
	s_bmpInfoHeader.biXPelsPerMeter = 2834; //72 dpi * 39.37
	s_bmpInfoHeader.biYPelsPerMeter = 2834; //72 dpi * 39.37
	s_bmpInfoHeader.biClrUsed = 0;			//Color pallete size
	s_bmpInfoHeader.biClrImportant = 0;		//

	fwrite((unsigned char *)(&s_bmpFileHeader),1,0x0E,fd);
	fwrite((unsigned char *)(&s_bmpInfoHeader),1,0x28,fd);
	return 0;
}


int32_t WriteRawFile(	char* szFileName,
                        unsigned int* pu32DstAddr,
                        unsigned int u32Width,
                        unsigned int u32Height)
{
	unsigned char* pi8BMP;
	FILE* fd = NULL;
	fd = fopen(szFileName,"wb+");
	if(NULL == fd) {
		printf("\n fopen() Error!!!\n");
		return -1;
	}
	pi8BMP=(unsigned char *)pu32DstAddr;
	fwrite((unsigned char *)(pi8BMP),1,(u32Width*u32Height*2),fd);
	fclose(fd);
}

int32_t WriteBmpFile(	char* szFileName,
                        unsigned int* pu32DstAddr,
                        unsigned int u32Width,
                        unsigned int u32Height)
{
	FILE* fd = NULL;
	unsigned int u32Idh, u32Idw;
	unsigned short* pu16Addr;
	unsigned char* pi8BMP;
	unsigned char* pi8Temp;
	int u32Padding=0;
	int32_t i32WriteLen;

	pi8Temp=pi8BMP=TmpBuffer;
	fd = fopen(szFileName,"wb+");
	if(NULL == fd) {
		printf("\n fopen() Error!!!\n");
		return -1;
	}

	WriteBitmapFileHeader(fd,u32Width,u32Height);

	if( (u32Width*3)%4==0)
		u32Padding = 0;
	else if( (u32Width*3)%4==1)
		u32Padding = 3;
	else if( (u32Width*3)%4==2)
		u32Padding = 2;
	else if( (u32Width*3)%4==3)
		u32Padding = 1;

	pu16Addr = (unsigned short*)pu32DstAddr;
	for(u32Idh=0; u32Idh<u32Height; u32Idh=u32Idh+1) {
		unsigned char u81stRGB[3];
		unsigned char u82ndRGB[3];
		for(u32Idw=0; u32Idw<u32Width; u32Idw=u32Idw+1) {
			//1 pixel, fmt=RGB565
			RGBToRGB888(*pu16Addr,
			            (unsigned int*)(&u81stRGB));
			pu16Addr = pu16Addr+1;
			memcpy((unsigned char *)pi8Temp, (unsigned char *)u81stRGB, 3);
			pi8Temp=pi8Temp+3;
			//fwrite((unsigned char *)(u81stRGB),1,3,fd);

		}
		//Add padding byte
		if(u32Padding==0)
			;
		else if (u32Padding==1)
			pi8Temp = pi8Temp + 1;
		else if (u32Padding==2)
			pi8Temp = pi8Temp + 2;
		else if (u32Padding==3)
			pi8Temp = pi8Temp + 3;
	}
	fwrite((unsigned char *)(pi8BMP),1,(u32Width*3+u32Padding)*u32Height,fd);
	fclose(fd);
	return 0;

}

static read_frame(char * filename)
{
	struct v4l2_buffer buf;
	int error;
	int i,j,k,l;

	CLEAR(buf);
	buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	buf.memory = V4L2_MEMORY_MMAP;
	if (-1 == xioctl(fd, VIDIOC_DQBUF, &buf)) {
		switch (errno) {
		case EAGAIN:
			printf("errno = EAGAIN\n");
			return 0;
		case EIO:
		default:
			errno_exit("VIDIOC_DQBUF");
		}
	}

	if(filename!=NULL) {
#if 1
		unsigned int *pRGB32 = (unsigned int *)buffers[buf.index].start;
		WriteBmpFile(filename,
		             pRGB32,
		             OUT_WIDTH,
		             OUT_HEIGHT);
#else
		unsigned int *pRGB32 = (unsigned int *)buffers[buf.index].start;
		WriteRawFile(filename,
		             pRGB32,
		             OUT_WIDTH,
		             OUT_HEIGHT);
#endif
	}

	if (-1 == xioctl(fd, VIDIOC_QBUF, &buf))
		errno_exit("VIDIOC_QBUF");
	return 1;
}

static void mainloop(void)
{
	int cnt=0;
	char filename[256];
	while(1) {
		sprintf(filename,"image%02d.bmp",cnt++);
		printf("Capture image to %s \n", filename);
		read_frame(filename);
		if(cnt>10) break;
	}
}

static void stop_capturing(void)
{
	enum v4l2_buf_type type;
	type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if (-1 == xioctl(fd, VIDIOC_STREAMOFF, &type))
		errno_exit("VIDIOC_STREAMOFF");
}

static void start_capturing(void)
{
	unsigned int i;
	enum v4l2_buf_type type;
	for (i = 0; i < n_buffers; ++i) {
		struct v4l2_buffer buf;
		CLEAR(buf);
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.index = i;
		if (-1 == xioctl(fd, VIDIOC_QBUF, &buf))
			errno_exit("VIDIOC_QBUF");
	}
	type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if (-1 == xioctl(fd, VIDIOC_STREAMON, &type))
		errno_exit("VIDIOC_STREAMON");
}

static void uninit_device(void)
{
	int i;
	for (i = 0; i < n_buffers; ++i)
		if (-1 == munmap(buffers[i].start, buffers[i].length))
			errno_exit("munmap");
	free(buffers);
}

static void init_mmap(void)
{

	struct v4l2_requestbuffers req;

	CLEAR(req);

	req.count = 4;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	req.memory = V4L2_MEMORY_MMAP;

	if (-1 == xioctl(fd, VIDIOC_REQBUFS, &req)) {
		if (EINVAL == errno) {
			printf("%s does not support memory mapping\n", dev_name);
			exit(EXIT_FAILURE);
		} else {
			errno_exit("VIDIOC_REQBUFS");
		}
	}

	if (req.count < 2) {
		printf("Insufficient buffer memory on %s", dev_name);
		exit(EXIT_FAILURE);
	}

	buffers = calloc(req.count, sizeof(*buffers));

	if (!buffers) {
		printf("Out of memory\n");
		exit(EXIT_FAILURE);
	}

	for (n_buffers = 0; n_buffers < req.count; ++n_buffers) {
		struct v4l2_buffer buf;
		CLEAR(buf);
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.index = n_buffers;
		if (-1 == xioctl(fd, VIDIOC_QUERYBUF, &buf))
			errno_exit("VIDIOC_QUERYBUF");
		buffers[n_buffers].length = buf.length;
		buffers[n_buffers].start = mmap(NULL /* start anywhere */,
		                                buf.length,
		                                PROT_READ | PROT_WRITE /* required */,
		                                MAP_SHARED /* recommended */,
		                                fd,
		                                buf.m.offset);
		if (MAP_FAILED == buffers[n_buffers].start)
			errno_exit("mmap");
	}
}

static void init_device(void)
{
	struct v4l2_capability cap;
	struct v4l2_cropcap cropcap;
	struct v4l2_crop crop;
	struct v4l2_format fmt;
	unsigned int min;
	if (-1 == xioctl(fd, VIDIOC_QUERYCAP, &cap)) {
		if (EINVAL == errno) {
			printf("%s is no V4L2 device/n", dev_name);
			exit(EXIT_FAILURE);
		} else {
			errno_exit("VIDIOC_QUERYCAP");
		}
	}

	if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE)) {
		printf("%s is no video capture device/n", dev_name);
		exit(EXIT_FAILURE);
	}

	if (!(cap.capabilities & V4L2_CAP_STREAMING)) {
		printf("%s does not support streaming i/o/n", dev_name);
		exit(EXIT_FAILURE);
	}
	/* Select video input, video standard and tune here. */
	CLEAR(cropcap);
	cropcap.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if (0 == xioctl(fd, VIDIOC_CROPCAP, &cropcap)) {
		crop.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		crop.c = cropcap.defrect; /* reset to default */
		if (-1 == xioctl(fd, VIDIOC_S_CROP, &crop)) {
			switch (errno) {
			case EINVAL:
				/* Cropping not supported. */
				break;
			default:
				/* Errors ignored. */
				break;
			}
		}
	} else {
		/* Errors ignored. */
	}

	CLEAR(fmt);
	fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	fmt.fmt.pix.width = OUT_WIDTH;
	fmt.fmt.pix.height = OUT_HEIGHT;
	fmt.fmt.pix.pixelformat = dev_fmt;
	fmt.fmt.pix.field = V4L2_FIELD_INTERLACED;

	if (-1 == xioctl(fd, VIDIOC_S_FMT, &fmt))
		errno_exit("VIDIOC_S_FMT");

	/* Buggy driver paranoia. */
	min = fmt.fmt.pix.width * 2;
	if (fmt.fmt.pix.bytesperline < min)
		fmt.fmt.pix.bytesperline = min;
	min = fmt.fmt.pix.bytesperline * fmt.fmt.pix.height;
	if (fmt.fmt.pix.sizeimage < min)
		fmt.fmt.pix.sizeimage = min;
	init_mmap();
}

static void close_device(void)
{
	close(fd);
	fd = -1;
}

static void open_device(void)
{
	struct stat st;

	if (-1 == stat(dev_name, &st)) {
		printf("Cannot identify '%s': %d, %s/n", dev_name, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!S_ISCHR(st.st_mode)) {
		printf("%s is no device/n", dev_name);
		exit(EXIT_FAILURE);
	}

	fd = open(dev_name, O_RDWR /* required */| O_NONBLOCK, 0);

	if (-1 == fd) {
		printf("Cannot open '%s': %d, %s/n", dev_name, errno,strerror(errno));
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char ** argv)
{
	dev_name = "/dev/video0";
	dev_fmt = V4L2_PIX_FMT_RGB565;

	open_device();

	init_device();

	start_capturing();

	mainloop();

	stop_capturing();

	uninit_device();

	close_device();

	exit(EXIT_SUCCESS);

	return 0;
}

